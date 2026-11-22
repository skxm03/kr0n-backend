package tests

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/skxm03/kr0n-backend/control-plane/internal/auth/repository"
)

func TestPostgresOutboxRepository_TokenRedactionAndPruning(t *testing.T) {
	pool := setupTestPool(t)
	repo := repository.NewPostgresOutboxRepository(pool)
	ctx := context.Background()

	rawToken1 := "secret_verification_token_xyz"
	ev1 := &repository.OutboxEvent{
		EventType:     repository.EventTypeEmailVerification,
		AggregateType: "user",
		AggregateID:   uuid.New(),
		Payload: map[string]any{
			"recipient": "user1@example.com",
			"data": map[string]any{
				"token": rawToken1,
			},
		},
		Status:      repository.OutboxStatusPending,
		CreatedAt:   time.Now().UTC(),
		ScheduledAt: time.Now().UTC(),
	}

	if err := repo.RecordEvent(ctx, ev1); err != nil {
		t.Fatalf("failed to record outbox event: %v", err)
	}

	// Verify before mark: payload contains raw token
	var payloadBytes []byte
	err := pool.QueryRow(ctx, "SELECT payload FROM outbox_events WHERE id = $1", ev1.ID).Scan(&payloadBytes)
	if err != nil {
		t.Fatalf("failed to query payload: %v", err)
	}
	var storedPayload map[string]any
	_ = json.Unmarshal(payloadBytes, &storedPayload)
	data, _ := storedPayload["data"].(map[string]any)
	if data["token"] != rawToken1 {
		t.Fatalf("expected raw token %q, got %v", rawToken1, data["token"])
	}

	// 1. Mark published -> token should be sanitized to [REDACTED]
	oldPublishedAt := time.Now().UTC().Add(-48 * time.Hour)
	if err := repo.MarkPublished(ctx, ev1.ID, oldPublishedAt); err != nil {
		t.Fatalf("MarkPublished failed: %v", err)
	}

	err = pool.QueryRow(ctx, "SELECT payload FROM outbox_events WHERE id = $1", ev1.ID).Scan(&payloadBytes)
	if err != nil {
		t.Fatalf("failed to query payload after publish: %v", err)
	}
	_ = json.Unmarshal(payloadBytes, &storedPayload)
	data, _ = storedPayload["data"].(map[string]any)
	if data["token"] != "[REDACTED]" {
		t.Fatalf("expected token to be redacted in payload, got %v", data["token"])
	}

	// 2. Mark permanent failure on ev2 -> token should also be redacted
	rawToken2 := "secret_reset_token_abc"
	ev2 := &repository.OutboxEvent{
		EventType:     repository.EventTypePasswordReset,
		AggregateType: "user",
		AggregateID:   uuid.New(),
		Payload: map[string]any{
			"recipient": "user2@example.com",
			"data": map[string]any{
				"token": rawToken2,
			},
		},
		Status:      repository.OutboxStatusProcessing,
		CreatedAt:   time.Now().UTC(),
		ScheduledAt: time.Now().UTC(),
	}
	if err := repo.RecordEvent(ctx, ev2); err != nil {
		t.Fatalf("failed to record outbox event 2: %v", err)
	}

	if err := repo.MarkFailed(ctx, ev2.ID, "permanent rejection", time.Now().UTC(), true); err != nil {
		t.Fatalf("MarkFailed failed: %v", err)
	}

	err = pool.QueryRow(ctx, "SELECT payload FROM outbox_events WHERE id = $1", ev2.ID).Scan(&payloadBytes)
	if err != nil {
		t.Fatalf("failed to query payload after permanent failure: %v", err)
	}
	_ = json.Unmarshal(payloadBytes, &storedPayload)
	data, _ = storedPayload["data"].(map[string]any)
	if data["token"] != "[REDACTED]" {
		t.Fatalf("expected token to be redacted after permanent failure, got %v", data["token"])
	}

	// 3. Prune published events older than 24 hours -> ev1 should be pruned, ev2 (failed) kept
	pruned, err := repo.PrunePublished(ctx, 24*time.Hour)
	if err != nil {
		t.Fatalf("PrunePublished failed: %v", err)
	}
	if pruned < 1 {
		t.Fatalf("expected at least 1 event pruned, got %d", pruned)
	}

	var count int
	_ = pool.QueryRow(ctx, "SELECT COUNT(*) FROM outbox_events WHERE id = $1", ev1.ID).Scan(&count)
	if count != 0 {
		t.Fatalf("expected ev1 to be pruned from outbox_events, got count = %d", count)
	}

	_ = pool.QueryRow(ctx, "SELECT COUNT(*) FROM outbox_events WHERE id = $1", ev2.ID).Scan(&count)
	if count != 1 {
		t.Fatalf("expected ev2 to remain in outbox_events, got count = %d", count)
	}
}
