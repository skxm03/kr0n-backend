package tests

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/skxm03/kr0n-backend/control-plane/internal/auth/repository"
	"github.com/skxm03/kr0n-backend/control-plane/internal/auth/service"
	"github.com/skxm03/kr0n-backend/control-plane/internal/testdb"
	pkgAudit "github.com/skxm03/kr0n-backend/control-plane/pkg/audit"
)

type memAuditRepo struct {
	mu     sync.Mutex
	events []repository.AuditEvent
}

func (m *memAuditRepo) Insert(_ context.Context, ev repository.AuditEvent) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = append(m.events, ev)
	return nil
}

func (m *memAuditRepo) ListByOrg(_ context.Context, orgID uuid.UUID, action string, limit, offset int) ([]repository.AuditEvent, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var filtered []repository.AuditEvent
	for i := len(m.events) - 1; i >= 0; i-- {
		ev := m.events[i]
		if ev.OrganizationID != nil && *ev.OrganizationID == orgID && (action == "" || ev.Action == action) {
			filtered = append(filtered, ev)
		}
	}
	if offset >= len(filtered) {
		return nil, nil
	}
	end := offset + limit
	if end > len(filtered) {
		end = len(filtered)
	}
	return filtered[offset:end], nil
}

func TestAuditService_RecordAndListByOrg(t *testing.T) {
	repo := &memAuditRepo{}
	svc := service.NewAuditService(repo)
	ctx := context.Background()

	org1 := uuid.New()
	org2 := uuid.New()
	actor := uuid.New()

	if err := svc.Record(ctx, repository.AuditEvent{
		OrganizationID: &org1,
		ActorUserID:    &actor,
		Action:         "apitoken.created",
		ResourceType:   "api_token",
		ResourceID:     "tok-1",
		Metadata:       map[string]any{"name": "ci"},
	}); err != nil {
		t.Fatalf("Record failed: %v", err)
	}
	if err := svc.Record(ctx, repository.AuditEvent{
		OrganizationID: &org2,
		ActorUserID:    &actor,
		Action:         "org.created",
		ResourceType:   "organization",
		ResourceID:     org2.String(),
	}); err != nil {
		t.Fatalf("Record org2 failed: %v", err)
	}

	events, err := svc.ListByOrg(ctx, org1, "", 10, 0)
	if err != nil {
		t.Fatalf("ListByOrg: %v", err)
	}
	if len(events) != 1 || events[0].Action != "apitoken.created" || events[0].ActorType != repository.ActorTypeUser {
		t.Fatalf("unexpected events: %+v", events)
	}
}

func TestAuditService_WithAuditEmitter(t *testing.T) {
	repo := &memAuditRepo{}
	emitter := pkgAudit.NewMemoryEmitter("auth")
	svc := service.NewAuditService(repo, service.WithAuditEmitter(emitter))
	ctx := context.Background()

	orgID := uuid.New()
	actorID := uuid.New()
	if err := svc.Record(ctx, repository.AuditEvent{
		OrganizationID: &orgID,
		ActorUserID:    &actorID,
		Action:         "org.created",
		ResourceType:   "organization",
		ResourceID:     orgID.String(),
		Metadata:       map[string]any{"request_id": "req-100"},
	}); err != nil {
		t.Fatalf("Record with emitter failed: %v", err)
	}

	// Repository Insert must NOT be called directly when emitter is configured
	if len(repo.events) != 0 {
		t.Fatalf("expected repo to have 0 direct inserts when emitter is used, got %d", len(repo.events))
	}
	emitted := emitter.Events()
	if len(emitted) != 1 {
		t.Fatalf("expected 1 emitted event, got %d", len(emitted))
	}
	if emitted[0].Action != "org.created" || emitted[0].Service != "auth" || emitted[0].ClientContext.RequestID != "req-100" {
		t.Fatalf("unexpected emitted event: %+v", emitted[0])
	}
}

func TestAuditPostgresActionFilter(t *testing.T) {
	pool := testdb.Pool(t)
	svc := service.NewAuditService(repository.NewPostgresAuditRepository(pool))
	ctx := context.Background()
	org, other := uuid.New(), uuid.New()
	for _, id := range []uuid.UUID{org, other} {
		if _, err := pool.Exec(ctx, "INSERT INTO organizations (id, name, slug) VALUES ($1, 'Audit test', $2)", id, id.String()); err != nil {
			t.Fatal(err)
		}
	}

	// Distinct timestamps make the order deterministic. Both unrelated rows are newer
	// than the matches, so filtering after pagination or dropping org scope fails.
	events := []repository.AuditEvent{
		{OrganizationID: &org, Action: "invite.revoked"},
		{OrganizationID: &org, Action: "invite.revoked"},
		{OrganizationID: &org, Action: "invite.created"},
		{OrganizationID: &other, Action: "invite.revoked"},
	}
	for i := range events {
		ev := &events[i]
		ev.ID = uuid.New()
		ev.CreatedAt = time.Unix(int64(i+1), 0)
		ev.ResourceType = "invite"
		if err := svc.Record(ctx, *ev); err != nil {
			t.Fatal(err)
		}
	}

	for _, tc := range []struct {
		name   string
		action string
		limit  int
		offset int
		want   []uuid.UUID
	}{
		{name: "first filtered page", action: "invite.revoked", limit: 1, want: []uuid.UUID{events[1].ID}},
		{name: "second filtered page", action: "invite.revoked", limit: 1, offset: 1, want: []uuid.UUID{events[0].ID}},
		{name: "filtered pages exhausted", action: "invite.revoked", limit: 1, offset: 2},
		{name: "all matches in this org", action: "invite.revoked", limit: 20, want: []uuid.UUID{events[1].ID, events[0].ID}},
		{name: "unknown action", action: "unknown.action", limit: 20},
		{name: "prefix is not a match", action: "invite", limit: 20},
		{name: "wildcard is literal", action: "invite.%", limit: 20},
		{name: "case sensitive", action: "Invite.Revoked", limit: 20},
		{name: "whitespace is literal", action: " invite.revoked", limit: 20},
		{name: "SQL is literal", action: "' OR 1=1 --", limit: 20},
		{name: "unfiltered history", limit: 20, want: []uuid.UUID{events[2].ID, events[1].ID, events[0].ID}},
		{name: "unfiltered pagination", limit: 1, offset: 1, want: []uuid.UUID{events[1].ID}},
		{name: "pagination defaults", action: "invite.revoked", offset: -1, want: []uuid.UUID{events[1].ID, events[0].ID}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := svc.ListByOrg(ctx, org, tc.action, tc.limit, tc.offset)
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != len(tc.want) {
				t.Fatalf("got %d events, want %d: %+v", len(got), len(tc.want), got)
			}
			for i, id := range tc.want {
				if got[i].ID != id {
					t.Errorf("event %d: got %s, want %s", i, got[i].ID, id)
				}
			}
		})
	}
}

func TestAuditPostgres_IdempotentDuplicateInsert(t *testing.T) {
	pool := testdb.Pool(t)
	repo := repository.NewPostgresAuditRepository(pool)
	ctx := context.Background()

	orgID := uuid.New()
	if _, err := pool.Exec(ctx, "INSERT INTO organizations (id, name, slug) VALUES ($1, 'Idempotency Test Org', $2)", orgID, orgID.String()); err != nil {
		t.Fatal(err)
	}

	eventID := uuid.New()
	ev := repository.AuditEvent{
		ID:             eventID,
		OrganizationID: &orgID,
		Action:         "user.login",
		ResourceType:   "user",
		ResourceID:     "user-123",
		CreatedAt:      time.Now().UTC(),
		Metadata:       map[string]any{"source": "test"},
	}

	// First insert
	if err := repo.Insert(ctx, ev); err != nil {
		t.Fatalf("first insert failed: %v", err)
	}

	// Duplicate insert with same ID should not error (ON CONFLICT (id) DO NOTHING)
	if err := repo.Insert(ctx, ev); err != nil {
		t.Fatalf("duplicate insert failed (expected ON CONFLICT DO NOTHING): %v", err)
	}

	// Verify only 1 row was stored and metadata was enriched with defaults
	events, err := repo.ListByOrg(ctx, orgID, "user.login", 10, 0)
	if err != nil {
		t.Fatalf("ListByOrg failed: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event due to deduplication, got %d", len(events))
	}
	if events[0].ID != eventID {
		t.Fatalf("expected event ID %s, got %s", eventID, events[0].ID)
	}
	if events[0].Metadata["service"] != "auth" {
		t.Errorf("expected default metadata service=auth, got %v", events[0].Metadata["service"])
	}
	if events[0].Metadata["status"] != "success" {
		t.Errorf("expected default metadata status=success, got %v", events[0].Metadata["status"])
	}
}
