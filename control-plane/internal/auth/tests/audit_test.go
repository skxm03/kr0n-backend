package tests

import (
	"context"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/skxm03/kr0n-backend/control-plane/internal/auth/repository"
	"github.com/skxm03/kr0n-backend/control-plane/internal/auth/service"
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

func (m *memAuditRepo) ListByOrg(_ context.Context, orgID uuid.UUID, limit, offset int) ([]repository.AuditEvent, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var filtered []repository.AuditEvent
	for i := len(m.events) - 1; i >= 0; i-- {
		ev := m.events[i]
		if ev.OrganizationID != nil && *ev.OrganizationID == orgID {
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

	events, err := svc.ListByOrg(ctx, org1, 10, 0)
	if err != nil {
		t.Fatalf("ListByOrg: %v", err)
	}
	if len(events) != 1 || events[0].Action != "apitoken.created" || events[0].ActorType != repository.ActorTypeUser {
		t.Fatalf("unexpected events: %+v", events)
	}
}
