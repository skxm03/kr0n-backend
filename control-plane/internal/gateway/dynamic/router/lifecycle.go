package router

import (
	"net/http"
	"sync"
	"time"

	"google.golang.org/grpc"
)

// Snapshot represents an immutable router snapshot with its associated gRPC connections
// and request lifecycle tracking.
type Snapshot struct {
	mu         sync.Mutex
	router     http.Handler
	conns      []*grpc.ClientConn
	retired    bool
	inFlight   int64
	idleNotify chan struct{}
	idleOnce   sync.Once
}

// NewSnapshot constructs a new Snapshot with the given router and gRPC connections.
func NewSnapshot(router http.Handler, conns []*grpc.ClientConn) *Snapshot {
	return &Snapshot{
		router:     router,
		conns:      conns,
		idleNotify: make(chan struct{}),
	}
}

// Router returns the underlying HTTP handler router compiled for this snapshot.
func (s *Snapshot) Router() http.Handler {
	return s.router
}

// Acquire increments the in-flight request counter if the snapshot is not retired.
// Returns false if the snapshot has already been retired.
func (s *Snapshot) Acquire() bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.retired {
		return false
	}
	s.inFlight++
	return true
}

// Release decrements the in-flight request counter. If the snapshot is retired and
// the count reaches zero, it notifies WaitAndClose.
func (s *Snapshot) Release() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.inFlight--
	if s.retired && s.inFlight <= 0 {
		s.idleOnce.Do(func() {
			close(s.idleNotify)
		})
	}
}

// Retire marks the snapshot as retired so no new requests can acquire it.
// If there are no active in-flight requests, it immediately notifies idle waiters.
func (s *Snapshot) Retire() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.retired = true
	if s.inFlight <= 0 {
		s.idleOnce.Do(func() {
			close(s.idleNotify)
		})
	}
}

// InFlight returns the current number of in-flight requests for testing/diagnostics.
func (s *Snapshot) InFlight() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.inFlight
}

// IsRetired returns whether the snapshot is retired.
func (s *Snapshot) IsRetired() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.retired
}

// WaitAndClose waits for all active in-flight requests to complete (or for the safety timeout
// to expire), then closes all underlying gRPC connections.
func (s *Snapshot) WaitAndClose(safetyTimeout time.Duration) {
	if safetyTimeout <= 0 {
		safetyTimeout = 30 * time.Second
	}

	select {
	case <-s.idleNotify:
		// All in-flight requests drained naturally.
	case <-time.After(safetyTimeout):
		// Safety timeout reached.
	}

	for _, conn := range s.conns {
		if conn != nil {
			_ = conn.Close()
		}
	}
}
