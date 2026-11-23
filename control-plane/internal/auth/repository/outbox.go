package repository

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// OutboxRepository defines persistence operations for transactional outbox events.
type OutboxRepository interface {
	RecordEventTx(ctx context.Context, tx pgx.Tx, ev *OutboxEvent) error
	RecordEvent(ctx context.Context, ev *OutboxEvent) error
	FetchPending(ctx context.Context, limit int, now time.Time) ([]*OutboxEvent, error)
	MarkPublished(ctx context.Context, id uuid.UUID, publishedAt time.Time) error
	MarkFailed(ctx context.Context, id uuid.UUID, lastErr string, nextSchedule time.Time, permanentlyFailed bool) error
	ReapStaleProcessing(ctx context.Context, olderThan time.Duration) (int64, error)
	PrunePublished(ctx context.Context, olderThan time.Duration) (int64, error)
}

// PostgresOutboxRepository implements OutboxRepository using PostgreSQL.
type PostgresOutboxRepository struct {
	pool *pgxpool.Pool
}

// NewPostgresOutboxRepository constructs a PostgresOutboxRepository.
func NewPostgresOutboxRepository(pool *pgxpool.Pool) *PostgresOutboxRepository {
	return &PostgresOutboxRepository{pool: pool}
}

// RecordDomainEventTx writes a domain event to the transactional outbox table within an active database transaction.
func RecordDomainEventTx(ctx context.Context, tx pgx.Tx, ev DomainEvent, now time.Time) error {
	if ev == nil {
		return nil
	}
	outboxEv := ev.ToOutboxEvent(now)
	if outboxEv == nil {
		return nil
	}
	return insertOutboxEventTx(ctx, tx, outboxEv)
}

func insertOutboxEventTx(ctx context.Context, tx pgx.Tx, ev *OutboxEvent) error {
	if ev == nil {
		return nil
	}
	if ev.ID == uuid.Nil {
		id, err := uuid.NewV7()
		if err != nil {
			id = uuid.New()
		}
		ev.ID = id
	}
	if ev.CreatedAt.IsZero() {
		ev.CreatedAt = time.Now().UTC()
	}
	if ev.ScheduledAt.IsZero() {
		ev.ScheduledAt = ev.CreatedAt
	}
	if ev.Status == "" {
		ev.Status = OutboxStatusPending
	}
	if ev.Payload == nil {
		ev.Payload = map[string]any{}
	}
	if ev.Headers == nil {
		ev.Headers = map[string]any{}
	}

	payloadJSON, err := json.Marshal(ev.Payload)
	if err != nil {
		return fmt.Errorf("marshal outbox payload: %w", err)
	}
	headersJSON, err := json.Marshal(ev.Headers)
	if err != nil {
		return fmt.Errorf("marshal outbox headers: %w", err)
	}

	const insertSQL = `
		INSERT INTO outbox_events (
			id, event_type, aggregate_type, aggregate_id,
			payload, headers, status, retry_count,
			created_at, scheduled_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10);
	`
	_, err = tx.Exec(ctx, insertSQL,
		ev.ID,
		ev.EventType,
		ev.AggregateType,
		ev.AggregateID,
		payloadJSON,
		headersJSON,
		ev.Status,
		ev.RetryCount,
		ev.CreatedAt,
		ev.ScheduledAt,
	)
	if err != nil {
		return fmt.Errorf("insert outbox event: %w", err)
	}
	return nil
}

// RecordEventTx writes an outbox event within an existing database transaction.
func (r *PostgresOutboxRepository) RecordEventTx(ctx context.Context, tx pgx.Tx, ev *OutboxEvent) error {
	return insertOutboxEventTx(ctx, tx, ev)
}

// RecordEvent writes an outbox event in its own transaction.
func (r *PostgresOutboxRepository) RecordEvent(ctx context.Context, ev *OutboxEvent) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin outbox tx: %w", err)
	}
	defer tx.Rollback(ctx)

	if err := r.RecordEventTx(ctx, tx, ev); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// FetchPending retrieves up to limit pending or retryable failed events and transitions them to 'processing' atomically.
func (r *PostgresOutboxRepository) FetchPending(ctx context.Context, limit int, now time.Time) ([]*OutboxEvent, error) {
	if limit <= 0 {
		limit = 50
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}

	const fetchSQL = `
		WITH selected AS (
			SELECT id
			FROM outbox_events
			WHERE status IN ('pending', 'failed') AND scheduled_at <= $1
			ORDER BY scheduled_at ASC, created_at ASC
			LIMIT $2
			FOR UPDATE SKIP LOCKED
		)
		UPDATE outbox_events o
		SET status = 'processing'
		FROM selected
		WHERE o.id = selected.id
		RETURNING o.id, o.event_type, o.aggregate_type, o.aggregate_id,
		          o.payload, o.headers, o.status, o.retry_count,
		          o.last_error, o.created_at, o.scheduled_at, o.published_at;
	`

	rows, err := r.pool.Query(ctx, fetchSQL, now, limit)
	if err != nil {
		return nil, fmt.Errorf("fetch pending outbox events: %w", err)
	}
	defer rows.Close()

	var events []*OutboxEvent
	for rows.Next() {
		var (
			ev         OutboxEvent
			payloadRaw []byte
			headersRaw []byte
		)
		if err := rows.Scan(
			&ev.ID,
			&ev.EventType,
			&ev.AggregateType,
			&ev.AggregateID,
			&payloadRaw,
			&headersRaw,
			&ev.Status,
			&ev.RetryCount,
			&ev.LastError,
			&ev.CreatedAt,
			&ev.ScheduledAt,
			&ev.PublishedAt,
		); err != nil {
			return nil, fmt.Errorf("scan outbox event: %w", err)
		}

		if len(payloadRaw) > 0 {
			if err := json.Unmarshal(payloadRaw, &ev.Payload); err != nil {
				return nil, fmt.Errorf("unmarshal payload: %w", err)
			}
		}
		if len(headersRaw) > 0 {
			if err := json.Unmarshal(headersRaw, &ev.Headers); err != nil {
				return nil, fmt.Errorf("unmarshal headers: %w", err)
			}
		}

		events = append(events, &ev)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate outbox rows: %w", err)
	}

	return events, nil
}

// MarkPublished marks an outbox event as successfully dispatched and sanitizes sensitive plaintext tokens in payload.
func (r *PostgresOutboxRepository) MarkPublished(ctx context.Context, id uuid.UUID, publishedAt time.Time) error {
	if publishedAt.IsZero() {
		publishedAt = time.Now().UTC()
	}
	const updateSQL = `
		UPDATE outbox_events
		SET status = 'published',
		    published_at = $2,
		    last_error = NULL,
		    payload = (
		        CASE
		            WHEN payload #> '{data,token}' IS NOT NULL THEN jsonb_set(payload, '{data,token}', '"[REDACTED]"'::jsonb)
		            WHEN payload ? 'token' THEN jsonb_set(payload, '{token}', '"[REDACTED]"'::jsonb)
		            ELSE payload
		        END
		    )
		WHERE id = $1;
	`
	_, err := r.pool.Exec(ctx, updateSQL, id, publishedAt)
	if err != nil {
		return fmt.Errorf("mark outbox published: %w", err)
	}
	return nil
}

// MarkFailed increments the retry count and records the error with a scheduled retry timestamp.
// If permanentlyFailed is true, sensitive tokens in the payload are redacted to avoid plaintext token leakage.
func (r *PostgresOutboxRepository) MarkFailed(ctx context.Context, id uuid.UUID, lastErr string, nextSchedule time.Time, permanentlyFailed bool) error {
	status := OutboxStatusFailed
	if permanentlyFailed {
		nextSchedule = time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC)
	}
	const updateSQL = `
		UPDATE outbox_events
		SET status = $2,
		    retry_count = retry_count + 1,
		    last_error = $3,
		    scheduled_at = $4,
		    payload = CASE
		        WHEN $5 = true THEN (
		            CASE
		                WHEN payload #> '{data,token}' IS NOT NULL THEN jsonb_set(payload, '{data,token}', '"[REDACTED]"'::jsonb)
		                WHEN payload ? 'token' THEN jsonb_set(payload, '{token}', '"[REDACTED]"'::jsonb)
		                ELSE payload
		            END
		        )
		        ELSE payload
		    END
		WHERE id = $1;
	`
	_, err := r.pool.Exec(ctx, updateSQL, id, status, lastErr, nextSchedule, permanentlyFailed)
	if err != nil {
		return fmt.Errorf("mark outbox failed: %w", err)
	}
	return nil
}

// ReapStaleProcessing recovers events left stuck in 'processing' by a crashed worker.
func (r *PostgresOutboxRepository) ReapStaleProcessing(ctx context.Context, olderThan time.Duration) (int64, error) {
	cutoff := time.Now().UTC().Add(-olderThan)
	const reapSQL = `
		UPDATE outbox_events
		SET status = 'pending'
		WHERE status = 'processing' AND scheduled_at <= $1;
	`
	tag, err := r.pool.Exec(ctx, reapSQL, cutoff)
	if err != nil {
		return 0, fmt.Errorf("reap stale outbox processing: %w", err)
	}
	return tag.RowsAffected(), nil
}

// PrunePublished deletes published outbox events that are older than olderThan duration.
func (r *PostgresOutboxRepository) PrunePublished(ctx context.Context, olderThan time.Duration) (int64, error) {
	cutoff := time.Now().UTC().Add(-olderThan)
	const pruneSQL = `
		DELETE FROM outbox_events
		WHERE status = 'published' AND published_at <= $1;
	`
	tag, err := r.pool.Exec(ctx, pruneSQL, cutoff)
	if err != nil {
		return 0, fmt.Errorf("prune published outbox events: %w", err)
	}
	return tag.RowsAffected(), nil
}
