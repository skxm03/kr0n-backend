package mailer

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	amqp "github.com/rabbitmq/amqp091-go"

	"github.com/skxm03/kr0n-backend/control-plane/internal/email"
)

type fakeAcknowledger struct {
	mu      sync.Mutex
	acked   map[uint64]bool
	nacked  map[uint64]bool
	requeue map[uint64]bool
}

func newFakeAcknowledger() *fakeAcknowledger {
	return &fakeAcknowledger{
		acked:   make(map[uint64]bool),
		nacked:  make(map[uint64]bool),
		requeue: make(map[uint64]bool),
	}
}

func (f *fakeAcknowledger) Ack(tag uint64, _ bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.acked[tag] = true
	return nil
}

func (f *fakeAcknowledger) Nack(tag uint64, _ bool, requeue bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.nacked[tag] = true
	f.requeue[tag] = requeue
	return nil
}

func (f *fakeAcknowledger) Reject(tag uint64, requeue bool) error {
	return f.Nack(tag, false, requeue)
}

type fakeDispatcher struct {
	mu          sync.Mutex
	dispatched  []RenderedEmail
	inFlight    atomic.Int32
	maxInFlight atomic.Int32
	delay       time.Duration
	failFor     map[string]error
}

func (d *fakeDispatcher) DispatchMIME(_ context.Context, recipient, subject, textBody, htmlBody string) error {
	cur := d.inFlight.Add(1)
	for {
		prev := d.maxInFlight.Load()
		if cur <= prev || d.maxInFlight.CompareAndSwap(prev, cur) {
			break
		}
	}
	defer d.inFlight.Add(-1)

	if d.delay > 0 {
		time.Sleep(d.delay)
	}

	d.mu.Lock()
	defer d.mu.Unlock()
	if err, ok := d.failFor[recipient]; ok {
		return err
	}
	d.dispatched = append(d.dispatched, RenderedEmail{
		Recipient: recipient,
		Subject:   subject,
		TextBody:  textBody,
		HTMLBody:  htmlBody,
	})
	return nil
}

func TestBatchProcessor_SizeAndTimeoutFlushWithBoundedConcurrency(t *testing.T) {
	engine, err := NewEngine()
	if err != nil {
		t.Fatalf("NewEngine() error: %v", err)
	}

	disp := &fakeDispatcher{
		delay:   15 * time.Millisecond,
		failFor: map[string]error{"fail@example.com": errors.New("smtp timeout")},
	}
	bp := NewBatchProcessor(engine, disp, BatchConfig{
		BatchSize:    4,
		BatchTimeout: 40 * time.Millisecond,
		Workers:      2,
	})

	ack := newFakeAcknowledger()
	deliveries := make(chan amqp.Delivery, 10)

	makeDelivery := func(tag uint64, job email.JobMessage) amqp.Delivery {
		b, _ := json.Marshal(job)
		return amqp.Delivery{
			Acknowledger: ack,
			DeliveryTag:  tag,
			Body:         b,
		}
	}

	// Enqueue 4 valid jobs (triggers BatchSize=4 flush) + 1 failing job + 1 malformed JSON job (flushed by BatchTimeout/close)
	for i := uint64(1); i <= 4; i++ {
		deliveries <- makeDelivery(i, email.JobMessage{
			ID:        "id",
			Type:      email.TemplateVerifyEmail,
			Recipient: "user@example.com",
			Data:      map[string]string{"token": "tok-123"},
		})
	}
	deliveries <- makeDelivery(5, email.JobMessage{
		ID:        "fail-id",
		Type:      email.TemplatePasswordReset,
		Recipient: "fail@example.com",
		Data:      map[string]string{"token": "tok-456"},
	})
	deliveries <- amqp.Delivery{
		Acknowledger: ack,
		DeliveryTag:  6,
		Body:         []byte("{malformed-json"),
	}
	close(deliveries)

	if err := bp.Run(context.Background(), deliveries); err != nil {
		t.Fatalf("Run() error: %v", err)
	}

	if got := len(disp.dispatched); got != 4 {
		t.Fatalf("dispatched count = %d, want 4", got)
	}
	if maxWorkers := disp.maxInFlight.Load(); maxWorkers > 2 {
		t.Errorf("max concurrent workers = %d, exceeded configured limit of 2", maxWorkers)
	}

	ack.mu.Lock()
	defer ack.mu.Unlock()
	for tag := uint64(1); tag <= 4; tag++ {
		if !ack.acked[tag] {
			t.Errorf("delivery %d was not Acked", tag)
		}
	}
	if !ack.nacked[5] || !ack.requeue[5] {
		t.Errorf("delivery 5 expected Nack with requeue=true on first failure, got nacked=%v requeue=%v", ack.nacked[5], ack.requeue[5])
	}
	if !ack.nacked[6] || ack.requeue[6] {
		t.Errorf("delivery 6 (malformed JSON) expected Nack with requeue=false (DLQ), got nacked=%v requeue=%v", ack.nacked[6], ack.requeue[6])
	}
}
