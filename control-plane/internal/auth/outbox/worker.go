package outbox

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/skxm03/kr0n-backend/control-plane/internal/auth/repository"
)

// Config defines operational parameters for the background outbox worker.
type Config struct {
	PollInterval time.Duration
	BatchSize    int
	MaxRetries   int
	BaseBackoff  time.Duration
	ReapInterval time.Duration
	StaleTimeout time.Duration
}

// DefaultConfig provides conservative production defaults.
func DefaultConfig() Config {
	return Config{
		PollInterval: 1 * time.Second,
		BatchSize:    50,
		MaxRetries:   5,
		BaseBackoff:  2 * time.Second,
		ReapInterval: 1 * time.Minute,
		StaleTimeout: 5 * time.Minute,
	}
}

// Worker executes background polling and dispatch of outbox events.
type Worker struct {
	repo      repository.OutboxRepository
	publisher Publisher
	cfg       Config
	notifyCh  chan struct{}
	mu        sync.Mutex
	running   bool
}

// NewWorker constructs a new outbox background worker.
func NewWorker(repo repository.OutboxRepository, publisher Publisher, cfg Config) *Worker {
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = 1 * time.Second
	}
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = 50
	}
	if cfg.MaxRetries <= 0 {
		cfg.MaxRetries = 5
	}
	if cfg.BaseBackoff <= 0 {
		cfg.BaseBackoff = 2 * time.Second
	}
	if cfg.ReapInterval <= 0 {
		cfg.ReapInterval = 1 * time.Minute
	}
	if cfg.StaleTimeout <= 0 {
		cfg.StaleTimeout = 5 * time.Minute
	}

	return &Worker{
		repo:      repo,
		publisher: publisher,
		cfg:       cfg,
		notifyCh:  make(chan struct{}, 1),
	}
}

// Notify triggers an immediate outbox processing pass without waiting for the poll interval.
func (w *Worker) Notify() {
	select {
	case w.notifyCh <- struct{}{}:
	default:
	}
}

// Start runs the worker event loop and blocks until ctx is canceled.
func (w *Worker) Start(ctx context.Context) error {
	w.mu.Lock()
	if w.running {
		w.mu.Unlock()
		return errors.New("outbox worker already running")
	}
	w.running = true
	w.mu.Unlock()

	defer func() {
		w.mu.Lock()
		w.running = false
		w.mu.Unlock()
	}()

	ticker := time.NewTicker(w.cfg.PollInterval)
	defer ticker.Stop()

	reapTicker := time.NewTicker(w.cfg.ReapInterval)
	defer reapTicker.Stop()

	// Initial sweep
	_, _ = w.ProcessBatch(ctx)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-w.notifyCh:
			_, _ = w.ProcessBatch(ctx)
		case <-ticker.C:
			_, _ = w.ProcessBatch(ctx)
		case <-reapTicker.C:
			if n, err := w.repo.ReapStaleProcessing(ctx, w.cfg.StaleTimeout); err == nil && n > 0 {
				log.Printf("outbox: reaped %d stale processing events", n)
			}
		}
	}
}

// ProcessBatch fetches and dispatches a batch of pending outbox events.
func (w *Worker) ProcessBatch(ctx context.Context) (int, error) {
	events, err := w.repo.FetchPending(ctx, w.cfg.BatchSize, time.Now().UTC())
	if err != nil {
		return 0, fmt.Errorf("fetch pending outbox events: %w", err)
	}
	if len(events) == 0 {
		return 0, nil
	}

	processed := 0
	for _, ev := range events {
		if ctx.Err() != nil {
			return processed, ctx.Err()
		}

		if err := w.publisher.Publish(ctx, ev); err != nil {
			log.Printf("outbox dispatch error for event %s (%s): %v", ev.ID, ev.EventType, err)
			permanentlyFailed := ev.RetryCount+1 >= w.cfg.MaxRetries
			backoff := w.cfg.BaseBackoff * (1 << ev.RetryCount)
			nextSchedule := time.Now().UTC().Add(backoff)

			if markErr := w.repo.MarkFailed(ctx, ev.ID, err.Error(), nextSchedule, permanentlyFailed); markErr != nil {
				log.Printf("outbox failed to mark event %s as failed: %v", ev.ID, markErr)
			}
		} else {
			if markErr := w.repo.MarkPublished(ctx, ev.ID, time.Now().UTC()); markErr != nil {
				log.Printf("outbox failed to mark event %s as published: %v", ev.ID, markErr)
			}
		}
		processed++
	}

	return processed, nil
}
