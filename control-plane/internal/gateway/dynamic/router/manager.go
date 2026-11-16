package router

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/skxm03/kr0n-backend/control-plane/internal/gateway/dynamic/config"
	"github.com/skxm03/kr0n-backend/control-plane/internal/gateway/dynamic/registry"
	"github.com/skxm03/kr0n-backend/control-plane/internal/gateway/middleware"
)

// ManagerOptions configures the dynamic snapshot Manager.
type ManagerOptions struct {
	Registry           *registry.Registry
	MiddlewareRegistry *middleware.Registry
	MuxFactory         MuxFactory
	Dialer             ServiceDialer
	ReadyCheck         func(context.Context) error
	SafetyTimeout      time.Duration
}

// Manager coordinates atomic snapshot replacement, safe in-flight request tracking,
// and HTTP dispatch.
type Manager struct {
	mu     sync.RWMutex
	active *Snapshot
	opts   ManagerOptions
}

// NewManager initializes a new dynamic router Manager.
func NewManager(opts ManagerOptions) *Manager {
	if opts.Registry == nil {
		opts.Registry = registry.DefaultRegistry()
	}
	if opts.MiddlewareRegistry == nil {
		opts.MiddlewareRegistry = middleware.NewRegistry()
	}
	if opts.SafetyTimeout <= 0 {
		opts.SafetyTimeout = 30 * time.Second
	}

	return &Manager{
		opts: opts,
	}
}

// Initialize compiles the initial Snapshot from GatewayConfig and activates it.
func (m *Manager) Initialize(ctx context.Context, cfg *config.GatewayConfig) error {
	snapshot, err := BuildSnapshot(ctx, cfg, SnapshotOptions{
		Registry:           m.opts.Registry,
		MiddlewareRegistry: m.opts.MiddlewareRegistry,
		MuxFactory:         m.opts.MuxFactory,
		Dialer:             m.opts.Dialer,
		ReadyCheck:         m.opts.ReadyCheck,
	})
	if err != nil {
		return fmt.Errorf("build initial snapshot: %w", err)
	}

	m.mu.Lock()
	m.active = snapshot
	m.mu.Unlock()

	return nil
}

// Acquire safely retrieves the current active Snapshot and increments its in-flight counter.
// Returns nil if no active snapshot is set or if the active snapshot is retired.
func (m *Manager) Acquire() *Snapshot {
	m.mu.RLock()
	defer m.mu.RUnlock()

	s := m.active
	if s == nil || !s.Acquire() {
		return nil
	}
	return s
}

// Swap atomically replaces the active snapshot with the new one and schedules
// safe connection closing for the retired snapshot once in-flight requests complete.
func (m *Manager) Swap(next *Snapshot) {
	m.mu.Lock()
	old := m.active
	m.active = next
	if old != nil {
		old.Retire()
	}
	m.mu.Unlock()

	if old != nil {
		go old.WaitAndClose(m.opts.SafetyTimeout)
	}
}

// Reload compiles a new Snapshot from the updated GatewayConfig. If compilation succeeds,
// it atomically swaps the snapshot; if compilation fails, the active snapshot remains untouched.
func (m *Manager) Reload(ctx context.Context, cfg *config.GatewayConfig) error {
	next, err := BuildSnapshot(ctx, cfg, SnapshotOptions{
		Registry:           m.opts.Registry,
		MiddlewareRegistry: m.opts.MiddlewareRegistry,
		MuxFactory:         m.opts.MuxFactory,
		Dialer:             m.opts.Dialer,
		ReadyCheck:         m.opts.ReadyCheck,
	})
	if err != nil {
		return fmt.Errorf("compile reload snapshot: %w", err)
	}

	m.Swap(next)
	return nil
}

// ActiveSnapshot returns the active Snapshot for inspection/testing.
func (m *Manager) ActiveSnapshot() *Snapshot {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.active
}

// ServeHTTP implements http.Handler, acquiring the active snapshot, dispatching the request,
// and releasing the snapshot upon completion.
func (m *Manager) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s := m.Acquire()
	if s == nil {
		http.Error(w, "gateway service unavailable", http.StatusServiceUnavailable)
		return
	}
	defer s.Release()

	s.router.ServeHTTP(w, r)
}

// Close gracefully closes the manager and its active snapshot.
func (m *Manager) Close() {
	m.mu.Lock()
	old := m.active
	m.active = nil
	if old != nil {
		old.Retire()
	}
	m.mu.Unlock()

	if old != nil {
		old.WaitAndClose(m.opts.SafetyTimeout)
	}
}
