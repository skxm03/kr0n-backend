package sinks

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"

	"github.com/skxm03/kr0n-backend/control-plane/internal/audit"
	pkgAudit "github.com/skxm03/kr0n-backend/control-plane/pkg/audit"
)

// MultiSink multiplexes audit event batches across multiple configured Sinks concurrently.
// It supports separating primary durable sinks from auxiliary streaming sinks so that
// auxiliary sink failures do not cause batch reprocessing or Dead Letter Queue routing.
type MultiSink struct {
	primary   []audit.Sink
	auxiliary []audit.Sink
}

// NewMultiSink creates a composite sink where all provided sinks are treated as primary.
func NewMultiSink(sinks ...audit.Sink) *MultiSink {
	return NewTieredMultiSink(sinks, nil)
}

// NewTieredMultiSink creates a composite sink with primary (critical) and auxiliary (best-effort) sinks.
// If all primary sinks succeed, failures in auxiliary sinks are logged as warnings and do not fail the batch.
func NewTieredMultiSink(primary []audit.Sink, auxiliary []audit.Sink) *MultiSink {
	filter := func(in []audit.Sink) []audit.Sink {
		out := make([]audit.Sink, 0, len(in))
		for _, s := range in {
			if s != nil {
				out = append(out, s)
			}
		}
		return out
	}
	p := filter(primary)
	a := filter(auxiliary)
	// If no primary sinks provided, promote auxiliary sinks to primary so the pipeline has at least one authoritative sink.
	if len(p) == 0 && len(a) > 0 {
		p = a
		a = nil
	}
	return &MultiSink{
		primary:   p,
		auxiliary: a,
	}
}

func (m *MultiSink) Name() string {
	names := make([]string, 0, len(m.primary)+len(m.auxiliary))
	for _, s := range m.primary {
		names = append(names, s.Name())
	}
	for _, s := range m.auxiliary {
		names = append(names, s.Name()+"(aux)")
	}
	return "multi(" + strings.Join(names, ",") + ")"
}

// WriteBatch fans out the batch concurrently across both primary and auxiliary sinks.
// It returns an error only if one or more primary sinks fail.
func (m *MultiSink) WriteBatch(ctx context.Context, events []pkgAudit.Event) error {
	if len(events) == 0 {
		return nil
	}
	allCount := len(m.primary) + len(m.auxiliary)
	if allCount == 0 {
		return nil
	}

	var (
		wg            sync.WaitGroup
		mu            sync.Mutex
		primaryErrs   []error
		auxiliaryErrs []error
	)

	for _, s := range m.primary {
		sink := s
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := sink.WriteBatch(ctx, events); err != nil {
				mu.Lock()
				primaryErrs = append(primaryErrs, fmt.Errorf("primary sink %s: %w", sink.Name(), err))
				mu.Unlock()
			}
		}()
	}

	for _, s := range m.auxiliary {
		sink := s
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := sink.WriteBatch(ctx, events); err != nil {
				mu.Lock()
				auxiliaryErrs = append(auxiliaryErrs, fmt.Errorf("auxiliary sink %s: %w", sink.Name(), err))
				mu.Unlock()
			}
		}()
	}

	wg.Wait()

	if len(auxiliaryErrs) > 0 {
		log.Printf("[audit-worker] warning: %d auxiliary sink(s) failed for batch: %v",
			len(auxiliaryErrs), errors.Join(auxiliaryErrs...))
	}

	if len(primaryErrs) > 0 {
		return errors.Join(primaryErrs...)
	}

	return nil
}

func (m *MultiSink) Close() error {
	var errs []error
	for _, s := range m.primary {
		if err := s.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close primary sink %s: %w", s.Name(), err))
		}
	}
	for _, s := range m.auxiliary {
		if err := s.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close auxiliary sink %s: %w", s.Name(), err))
		}
	}
	return errors.Join(errs...)
}
