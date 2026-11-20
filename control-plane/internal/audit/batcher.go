package audit

import (
	"context"
	"encoding/json"
	"log"
	"time"

	amqp "github.com/rabbitmq/amqp091-go"

	pkgAudit "github.com/skxm03/kr0n-backend/control-plane/pkg/audit"
)

// BatchConfig configures stateless batch accumulation and sink retry behavior.
type BatchConfig struct {
	BatchSize    int
	BatchTimeout time.Duration
	MaxRetries   int
	RetryBackoff time.Duration
}

// BatchProcessor statelessly collects RabbitMQ deliveries into batches, runs them through
// transformers, writes them to the configured Sink pipeline, and acknowledges deliveries.
type BatchProcessor struct {
	sink         Sink
	transformers []EventTransformer
	cfg          BatchConfig
}

// NewBatchProcessor creates a stateless BatchProcessor with sensible defaults.
func NewBatchProcessor(sink Sink, cfg BatchConfig, transformers ...EventTransformer) *BatchProcessor {
	if cfg.BatchSize < 1 {
		cfg.BatchSize = 100
	}
	if cfg.BatchTimeout <= 0 {
		cfg.BatchTimeout = 200 * time.Millisecond
	}
	if cfg.MaxRetries < 0 {
		cfg.MaxRetries = 3
	}
	if cfg.RetryBackoff <= 0 {
		cfg.RetryBackoff = 100 * time.Millisecond
	}
	return &BatchProcessor{
		sink:         sink,
		transformers: transformers,
		cfg:          cfg,
	}
}

// Run consumes deliveries until ctx is canceled or the deliveries channel closes,
// flushing a batch whenever BatchSize is reached or BatchTimeout elapses.
func (bp *BatchProcessor) Run(ctx context.Context, deliveries <-chan amqp.Delivery) error {
	batch := make([]amqp.Delivery, 0, bp.cfg.BatchSize)
	timer := time.NewTimer(bp.cfg.BatchTimeout)
	defer timer.Stop()

	flush := func() {
		if len(batch) == 0 {
			return
		}
		toProcess := make([]amqp.Delivery, len(batch))
		copy(toProcess, batch)
		batch = batch[:0]
		// Use a bounded detached context during shutdown so in-flight batches flush cleanly.
		flushCtx := ctx
		if flushCtx.Err() != nil {
			var cancel context.CancelFunc
			flushCtx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
		}
		bp.ProcessBatch(flushCtx, toProcess)
	}

	for {
		select {
		case <-ctx.Done():
			flush()
			return nil
		case d, ok := <-deliveries:
			if !ok {
				flush()
				return nil
			}
			if len(batch) == 0 {
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
				timer.Reset(bp.cfg.BatchTimeout)
			}
			batch = append(batch, d)
			if len(batch) >= bp.cfg.BatchSize {
				flush()
			}
		case <-timer.C:
			flush()
		}
	}
}

// ProcessBatch validates and transforms each delivery in the batch, routes malformed/invalid
// messages directly to the DLQ, and persists valid events to the sink pipeline with retry backoff.
func (bp *BatchProcessor) ProcessBatch(ctx context.Context, batch []amqp.Delivery) {
	if len(batch) == 0 {
		return
	}

	validEvents := make([]pkgAudit.Event, 0, len(batch))
	validDeliveries := make([]amqp.Delivery, 0, len(batch))

	for i := range batch {
		msg := batch[i]
		var ev pkgAudit.Event
		if err := json.Unmarshal(msg.Body, &ev); err != nil {
			log.Printf("[audit-worker] rejecting malformed JSON message %q (routed to dlq): %v", msg.MessageId, err)
			_ = msg.Nack(false, false)
			continue
		}

		defaultSvc := msg.AppId
		if defaultSvc == "" {
			defaultSvc = "unknown"
		}
		ev.Normalize(defaultSvc)

		if err := ev.Validate(); err != nil {
			log.Printf("[audit-worker] rejecting invalid audit event %q (action=%q service=%q): %v",
				ev.ID, ev.Action, ev.Service, err)
			_ = msg.Nack(false, false)
			continue
		}

		rejected := false
		for _, tr := range bp.transformers {
			if tr == nil {
				continue
			}
			var err error
			ev, err = tr(ev)
			if err != nil {
				log.Printf("[audit-worker] transformer rejected audit event %q: %v", ev.ID, err)
				_ = msg.Nack(false, false)
				rejected = true
				break
			}
		}
		if rejected {
			continue
		}

		validEvents = append(validEvents, ev)
		validDeliveries = append(validDeliveries, msg)
	}

	if len(validEvents) == 0 {
		return
	}

	if err := bp.writeWithRetry(ctx, validEvents); err != nil {
		log.Printf("[audit-worker] sink pipeline (%s) failed after %d retries for batch of %d events (routed to dlq): %v",
			bp.sink.Name(), bp.cfg.MaxRetries, len(validEvents), err)
		for i := range validDeliveries {
			_ = validDeliveries[i].Nack(false, false)
		}
		return
	}

	for i := range validDeliveries {
		_ = validDeliveries[i].Ack(false)
	}
}

func (bp *BatchProcessor) writeWithRetry(ctx context.Context, events []pkgAudit.Event) error {
	if bp.sink == nil {
		return nil
	}
	var lastErr error
	backoff := bp.cfg.RetryBackoff

	for attempt := 0; attempt <= bp.cfg.MaxRetries; attempt++ {
		if attempt > 0 {
			timer := time.NewTimer(backoff)
			select {
			case <-ctx.Done():
				timer.Stop()
				return ctx.Err()
			case <-timer.C:
			}
			backoff *= 2
		}

		lastErr = bp.sink.WriteBatch(ctx, events)
		if lastErr == nil {
			return nil
		}
	}
	return lastErr
}
