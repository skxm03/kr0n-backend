package audit

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	amqp "github.com/rabbitmq/amqp091-go"

	pkgAudit "github.com/skxm03/kr0n-backend/control-plane/pkg/audit"
)

type testSink struct {
	mu     sync.Mutex
	events []pkgAudit.Event
}

func (s *testSink) Name() string { return "test-sink" }

func (s *testSink) WriteBatch(_ context.Context, events []pkgAudit.Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, events...)
	return nil
}

func (s *testSink) Close() error { return nil }

func (s *testSink) Events() []pkgAudit.Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]pkgAudit.Event, len(s.events))
	copy(out, s.events)
	return out
}

func TestBatchProcessor_ReturnsErrBrokerDisconnectedOnUnexpectedChannelClose(t *testing.T) {
	sink := &testSink{}
	bp := NewBatchProcessor(sink, BatchConfig{
		BatchSize:    10,
		BatchTimeout: 100 * time.Millisecond,
	})

	deliveries := make(chan amqp.Delivery, 5)

	// Close the deliveries channel without canceling ctx
	close(deliveries)

	ctx := context.Background()
	err := bp.Run(ctx, deliveries)
	if !errors.Is(err, ErrBrokerDisconnected) {
		t.Fatalf("expected ErrBrokerDisconnected on premature channel closure, got: %v", err)
	}
}

func TestBatchProcessor_ReturnsNilOnGracefulContextCancel(t *testing.T) {
	sink := &testSink{}
	bp := NewBatchProcessor(sink, BatchConfig{
		BatchSize:    10,
		BatchTimeout: 100 * time.Millisecond,
	})

	deliveries := make(chan amqp.Delivery, 5)
	ctx, cancel := context.WithCancel(context.Background())

	// Cancel context first
	cancel()

	err := bp.Run(ctx, deliveries)
	if err != nil {
		t.Fatalf("expected nil on graceful context cancel, got: %v", err)
	}
}

type mockAck struct{}

func (m *mockAck) Ack(_ uint64, _ bool) error          { return nil }
func (m *mockAck) Nack(_ uint64, _ bool, _ bool) error { return nil }
func (m *mockAck) Reject(_ uint64, _ bool) error       { return nil }

func TestBatchProcessor_FlushesQueuedBatchBeforeBrokerDisconnected(t *testing.T) {
	sink := &testSink{}
	bp := NewBatchProcessor(sink, BatchConfig{
		BatchSize:    10,
		BatchTimeout: 5 * time.Second, // Long timeout: flush must be triggered by channel closure
	})

	deliveries := make(chan amqp.Delivery, 5)
	evBody := []byte(`{"service":"auth","action":"user.login","target":{"type":"user","id":"u-1"}}`)
	deliveries <- amqp.Delivery{Acknowledger: &mockAck{}, DeliveryTag: 1, Body: evBody}
	deliveries <- amqp.Delivery{Acknowledger: &mockAck{}, DeliveryTag: 2, Body: evBody}
	close(deliveries)

	ctx := context.Background()
	err := bp.Run(ctx, deliveries)
	if !errors.Is(err, ErrBrokerDisconnected) {
		t.Fatalf("expected ErrBrokerDisconnected, got: %v", err)
	}

	events := sink.Events()
	if len(events) != 2 {
		t.Fatalf("expected 2 flushed events before disconnection return, got %d", len(events))
	}
}
