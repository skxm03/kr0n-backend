package outbox

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/skxm03/kr0n-backend/control-plane/internal/auth/repository"
)

type mockOutboxRepo struct {
	mu           sync.Mutex
	events       []*repository.OutboxEvent
	publishedIDs []uuid.UUID
	failedIDs    map[uuid.UUID]string
	permanentIDs []uuid.UUID
}

func (m *mockOutboxRepo) RecordEventTx(ctx context.Context, tx pgx.Tx, ev *repository.OutboxEvent) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = append(m.events, ev)
	return nil
}

func (m *mockOutboxRepo) RecordEvent(ctx context.Context, ev *repository.OutboxEvent) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = append(m.events, ev)
	return nil
}

func (m *mockOutboxRepo) FetchPending(ctx context.Context, limit int, now time.Time) ([]*repository.OutboxEvent, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var pending []*repository.OutboxEvent
	for _, ev := range m.events {
		if (ev.Status == repository.OutboxStatusPending || ev.Status == repository.OutboxStatusFailed) && !ev.ScheduledAt.After(now) {
			ev.Status = repository.OutboxStatusProcessing
			pending = append(pending, ev)
			if len(pending) >= limit {
				break
			}
		}
	}
	return pending, nil
}

func (m *mockOutboxRepo) MarkPublished(ctx context.Context, id uuid.UUID, publishedAt time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.publishedIDs = append(m.publishedIDs, id)
	for _, ev := range m.events {
		if ev.ID == id {
			ev.Status = repository.OutboxStatusPublished
			ev.PublishedAt = &publishedAt
		}
	}
	return nil
}

func (m *mockOutboxRepo) MarkFailed(ctx context.Context, id uuid.UUID, lastErr string, nextSchedule time.Time, permanentlyFailed bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failedIDs == nil {
		m.failedIDs = make(map[uuid.UUID]string)
	}
	m.failedIDs[id] = lastErr
	if permanentlyFailed {
		m.permanentIDs = append(m.permanentIDs, id)
	}
	for _, ev := range m.events {
		if ev.ID == id {
			ev.Status = repository.OutboxStatusFailed
			ev.RetryCount++
			ev.LastError = &lastErr
			ev.ScheduledAt = nextSchedule
		}
	}
	return nil
}

func (m *mockOutboxRepo) ReapStaleProcessing(ctx context.Context, olderThan time.Duration) (int64, error) {
	return 0, nil
}

type mockPublisher struct {
	mu        sync.Mutex
	published []*repository.OutboxEvent
	failNext  error
}

func (p *mockPublisher) Publish(ctx context.Context, ev *repository.OutboxEvent) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.failNext != nil {
		err := p.failNext
		p.failNext = nil
		return err
	}
	p.published = append(p.published, ev)
	return nil
}

func TestWorker_ProcessBatch_Success(t *testing.T) {
	now := time.Now().UTC()
	id1 := uuid.New()
	id2 := uuid.New()

	repo := &mockOutboxRepo{
		events: []*repository.OutboxEvent{
			{ID: id1, EventType: repository.EventTypeEmailVerification, Status: repository.OutboxStatusPending, ScheduledAt: now},
			{ID: id2, EventType: repository.EventTypePasswordReset, Status: repository.OutboxStatusPending, ScheduledAt: now},
		},
	}
	pub := &mockPublisher{}

	w := NewWorker(repo, pub, Config{
		BatchSize:   10,
		MaxRetries:  3,
		BaseBackoff: 100 * time.Millisecond,
	})

	count, err := w.ProcessBatch(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if count != 2 {
		t.Fatalf("expected 2 processed, got %d", count)
	}

	if len(repo.publishedIDs) != 2 {
		t.Fatalf("expected 2 marked published, got %d", len(repo.publishedIDs))
	}
	if len(pub.published) != 2 {
		t.Fatalf("expected 2 published, got %d", len(pub.published))
	}
}

func TestWorker_ProcessBatch_RetryAndBackoff(t *testing.T) {
	now := time.Now().UTC()
	id := uuid.New()

	repo := &mockOutboxRepo{
		events: []*repository.OutboxEvent{
			{ID: id, EventType: repository.EventTypeEmailVerification, Status: repository.OutboxStatusPending, ScheduledAt: now, RetryCount: 0},
		},
	}
	pub := &mockPublisher{
		failNext: errors.New("rabbitmq connection lost"),
	}

	w := NewWorker(repo, pub, Config{
		BatchSize:   10,
		MaxRetries:  3,
		BaseBackoff: 100 * time.Millisecond,
	})

	count, err := w.ProcessBatch(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected 1 processed, got %d", count)
	}

	if len(repo.publishedIDs) != 0 {
		t.Fatalf("expected 0 published, got %d", len(repo.publishedIDs))
	}
	if repo.failedIDs[id] != "rabbitmq connection lost" {
		t.Fatalf("expected failed error recorded, got %q", repo.failedIDs[id])
	}
	if len(repo.permanentIDs) != 0 {
		t.Fatalf("expected not permanent failure yet, got %d", len(repo.permanentIDs))
	}
}

func TestWorker_ProcessBatch_PermanentFailure(t *testing.T) {
	now := time.Now().UTC()
	id := uuid.New()

	repo := &mockOutboxRepo{
		events: []*repository.OutboxEvent{
			{ID: id, EventType: repository.EventTypeEmailVerification, Status: repository.OutboxStatusFailed, ScheduledAt: now, RetryCount: 2},
		},
	}
	pub := &mockPublisher{
		failNext: errors.New("permanent schema rejection"),
	}

	w := NewWorker(repo, pub, Config{
		BatchSize:   10,
		MaxRetries:  3,
		BaseBackoff: 100 * time.Millisecond,
	})

	count, err := w.ProcessBatch(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected 1 processed, got %d", count)
	}

	if len(repo.permanentIDs) != 1 || repo.permanentIDs[0] != id {
		t.Fatalf("expected permanently failed id %v, got %v", id, repo.permanentIDs)
	}
}

func TestWorker_BackgroundLoopAndNotify(t *testing.T) {
	now := time.Now().UTC()
	id := uuid.New()

	repo := &mockOutboxRepo{
		events: []*repository.OutboxEvent{
			{ID: id, EventType: repository.EventTypeEmailVerification, Status: repository.OutboxStatusPending, ScheduledAt: now},
		},
	}
	pub := &mockPublisher{}

	w := NewWorker(repo, pub, Config{
		PollInterval: 10 * time.Second, // Long interval to prove Notify triggers it
		BatchSize:    10,
		MaxRetries:   3,
		BaseBackoff:  100 * time.Millisecond,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- w.Start(ctx)
	}()

	// Signal worker via Notify()
	w.Notify()

	// Wait for published event
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		repo.mu.Lock()
		count := len(repo.publishedIDs)
		repo.mu.Unlock()
		if count > 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	repo.mu.Lock()
	count := len(repo.publishedIDs)
	repo.mu.Unlock()
	if count != 1 {
		t.Fatalf("expected event published via notify, got %d", count)
	}

	// Cancel context to stop worker
	cancel()
	select {
	case err := <-done:
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Fatalf("unexpected stop error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("worker did not shut down in time")
	}
}
