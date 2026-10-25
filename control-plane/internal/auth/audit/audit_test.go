package audit

import (
	"context"
	"sync"
	"testing"

	"github.com/google/uuid"
)

type memRepo struct {
	mu     sync.Mutex
	events []Event
}

func (m *memRepo) Insert(_ context.Context, ev Event) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = append(m.events, ev)
	return nil
}

func (m *memRepo) ListByOrg(_ context.Context, orgID uuid.UUID, limit, offset int) ([]Event, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var filtered []Event
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

func TestService_RecordAndListByOrg(t *testing.T) {
	repo := &memRepo{}
	svc := NewService(repo)
	ctx := context.Background()

	org1 := uuid.New()
	org2 := uuid.New()
	actor := uuid.New()

	if err := svc.Record(ctx, Event{
		OrganizationID: &org1,
		ActorUserID:    &actor,
		Action:         "apitoken.created",
		ResourceType:   "api_token",
		ResourceID:     "tok-1",
		Metadata:       map[string]any{"name": "ci"},
	}); err != nil {
		t.Fatalf("Record failed: %v", err)
	}
	if err := svc.Record(ctx, Event{
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
	if len(events) != 1 || events[0].Action != "apitoken.created" || events[0].ActorType != ActorTypeUser {
		t.Fatalf("unexpected events: %+v", events)
	}
}
