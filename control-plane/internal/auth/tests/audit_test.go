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
