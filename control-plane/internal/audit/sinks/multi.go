package sinks

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/skxm03/kr0n-backend/control-plane/internal/audit"
	pkgAudit "github.com/skxm03/kr0n-backend/control-plane/pkg/audit"
)

// MultiSink multiplexes audit event batches across multiple configured Sinks concurrently.
type MultiSink struct {
	sinks []audit.Sink
}

// NewMultiSink creates a composite sink that fans out batches to all non-nil child sinks.
func NewMultiSink(sinks ...audit.Sink) *MultiSink {
	filtered := make([]audit.Sink, 0, len(sinks))
	for _, s := range sinks {
		if s != nil {
			filtered = append(filtered, s)
		}
	}
	return &MultiSink{sinks: filtered}
}

func (m *MultiSink) Name() string {
	names := make([]string, 0, len(m.sinks))
	for _, s := range m.sinks {
		names = append(names, s.Name())
	}
	return "multi(" + strings.Join(names, ",") + ")"
}

// WriteBatch fans out the batch concurrently to all child sinks and joins any errors.
func (m *MultiSink) WriteBatch(ctx context.Context, events []pkgAudit.Event) error {
	if len(events) == 0 || len(m.sinks) == 0 {
		return nil
	}
	if len(m.sinks) == 1 {
		return m.sinks[0].WriteBatch(ctx, events)
	}

	var (
		wg   sync.WaitGroup
		mu   sync.Mutex
		errs []error
	)

	for _, s := range m.sinks {
		sink := s
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := sink.WriteBatch(ctx, events); err != nil {
				mu.Lock()
				errs = append(errs, fmt.Errorf("sink %s: %w", sink.Name(), err))
				mu.Unlock()
			}
		}()
	}

	wg.Wait()
	return errors.Join(errs...)
}

func (m *MultiSink) Close() error {
	var errs []error
	for _, s := range m.sinks {
		if err := s.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close sink %s: %w", s.Name(), err))
		}
	}
	return errors.Join(errs...)
}
