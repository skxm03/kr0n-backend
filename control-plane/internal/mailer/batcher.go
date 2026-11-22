package mailer

import (
	"context"
	"encoding/json"
	"log"
	"sync"
	"time"

	amqp "github.com/rabbitmq/amqp091-go"

	"github.com/skxm03/kr0n-backend/control-plane/internal/email"
)

// Dispatcher sends a rendered email over SMTP (or a test double).
type Dispatcher interface {
	DispatchMIME(ctx context.Context, recipient, subject, textBody, htmlBody string) error
}

// BatchConfig configures batch collection and concurrent goroutine dispatch.
type BatchConfig struct {
	BatchSize    int
	BatchTimeout time.Duration
	Workers      int
	MaxRetries   int
	RetryBackoff time.Duration
}

// BatchProcessor collects RabbitMQ deliveries into batches and dispatches them concurrently
// using a bounded pool of goroutines.
type BatchProcessor struct {
	engine     *Engine
	dispatcher Dispatcher
	cfg        BatchConfig
}

// NewBatchProcessor creates a BatchProcessor with sensible fallbacks if fields are zero.
func NewBatchProcessor(engine *Engine, dispatcher Dispatcher, cfg BatchConfig) *BatchProcessor {
	if cfg.BatchSize < 1 {
		cfg.BatchSize = 20
	}
	if cfg.BatchTimeout <= 0 {
		cfg.BatchTimeout = 200 * time.Millisecond
	}
	if cfg.Workers < 1 {
		cfg.Workers = 8
	}
	if cfg.MaxRetries < 1 {
		cfg.MaxRetries = 3
	}
	if cfg.RetryBackoff <= 0 {
		cfg.RetryBackoff = 100 * time.Millisecond
	}
	return &BatchProcessor{
		engine:     engine,
		dispatcher: dispatcher,
		cfg:        cfg,
	}
}

// Run consumes deliveries until ctx is canceled or the deliveries channel closes,
// flushing a batch whenever BatchSize is reached or BatchTimeout elapses.
func (bp *BatchProcessor) Run(ctx context.Context, deliveries <-chan amqp.Delivery) error {
	batch := make([]amqp.Delivery, 0, bp.cfg.BatchSize)
	timer := time.NewTimer(bp.cfg.BatchTimeout)
	defer timer.Stop()

	flush := func(procCtx context.Context) {
		if len(batch) == 0 {
			return
		}
		toProcess := make([]amqp.Delivery, len(batch))
		copy(toProcess, batch)
		batch = batch[:0]
		bp.ProcessBatch(procCtx, toProcess)
	}

	for {
		select {
		case <-ctx.Done():
			drainCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			flush(drainCtx)
			cancel()
			return nil
		case d, ok := <-deliveries:
			if !ok {
				flush(ctx)
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
				flush(ctx)
			}
		case <-timer.C:
			flush(ctx)
		}
	}
}

// ProcessBatch processes a slice of RabbitMQ deliveries concurrently using a bounded worker pool
// of goroutines.
func (bp *BatchProcessor) ProcessBatch(ctx context.Context, batch []amqp.Delivery) {
	var wg sync.WaitGroup
	sem := make(chan struct{}, bp.cfg.Workers)

	for i := range batch {
		d := batch[i]
		wg.Add(1)
		sem <- struct{}{}
		go func(msg amqp.Delivery) {
			defer wg.Done()
			defer func() { <-sem }()
			bp.handleDelivery(ctx, msg)
		}(d)
	}

	wg.Wait()
}

func (bp *BatchProcessor) handleDelivery(ctx context.Context, msg amqp.Delivery) {
	if ctx.Err() != nil {
		// Shutdown or context canceled -> requeue rather than dropping to DLQ
		_ = msg.Nack(false, true)
		return
	}

	var job email.JobMessage
	if err := json.Unmarshal(msg.Body, &job); err != nil {
		log.Printf("[mailer] rejecting malformed JSON message %q: %v", msg.MessageId, err)
		_ = msg.Nack(false, false) // permanent validation error -> route to DLQ
		return
	}

	rendered, err := bp.engine.SanitizeAndRender(job)
	if err != nil {
		log.Printf("[mailer] rejecting invalid email job %q (type=%s): %v", job.ID, job.Type, err)
		_ = msg.Nack(false, false) // permanent validation error -> route to DLQ
		return
	}

	maxRetries := bp.cfg.MaxRetries
	if maxRetries < 1 {
		maxRetries = 3
	}
	baseBackoff := bp.cfg.RetryBackoff
	if baseBackoff <= 0 {
		baseBackoff = 100 * time.Millisecond
	}

	var lastErr error
	for attempt := 0; attempt < maxRetries; attempt++ {
		if ctx.Err() != nil {
			// Context canceled during retry loop -> requeue for another consumer
			_ = msg.Nack(false, true)
			return
		}

		if attempt > 0 {
			backoff := baseBackoff * (1 << (attempt - 1))
			select {
			case <-time.After(backoff):
			case <-ctx.Done():
				_ = msg.Nack(false, true)
				return
			}
		}

		lastErr = bp.dispatcher.DispatchMIME(ctx, rendered.Recipient, rendered.Subject, rendered.TextBody, rendered.HTMLBody)
		if lastErr == nil {
			_ = msg.Ack(false)
			return
		}
		log.Printf("[mailer] attempt %d/%d failed to send email job %q to %s: %v", attempt+1, maxRetries, job.ID, rendered.Recipient, lastErr)
	}

	// All retries exhausted -> route to DLQ
	log.Printf("[mailer] exhausted %d retries sending email job %q to %s (routed to dlq): %v", maxRetries, job.ID, rendered.Recipient, lastErr)
	_ = msg.Nack(false, false)
}
