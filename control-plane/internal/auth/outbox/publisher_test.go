package outbox

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/skxm03/kr0n-backend/control-plane/internal/auth/repository"
	"github.com/skxm03/kr0n-backend/control-plane/internal/email"
)

type mockEnqueuer struct {
	enqueued []email.JobMessage
}

func (m *mockEnqueuer) Enqueue(ctx context.Context, job email.JobMessage) error {
	m.enqueued = append(m.enqueued, job)
	return nil
}

func TestEmailPublisher_Enqueuer(t *testing.T) {
	enq := &mockEnqueuer{}
	pub := NewEmailPublisher(enq)

	now := time.Now().UTC()
	uid := uuid.New()

	// 1. Verification Email
	err := pub.Publish(context.Background(), &repository.OutboxEvent{
		ID:        uid,
		EventType: repository.EventTypeEmailVerification,
		Payload: map[string]any{
			"recipient": "alice@kr0n.dev",
			"data": map[string]any{
				"token": "tok_123",
			},
		},
		CreatedAt: now,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// 2. Password Reset
	err = pub.Publish(context.Background(), &repository.OutboxEvent{
		ID:        uid,
		EventType: repository.EventTypePasswordReset,
		Payload: map[string]any{
			"recipient": "bob@kr0n.dev",
			"data": map[string]any{
				"token": "tok_456",
			},
		},
		CreatedAt: now,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// 3. Org Invite
	err = pub.Publish(context.Background(), &repository.OutboxEvent{
		ID:        uid,
		EventType: repository.EventTypeOrgInvite,
		Payload: map[string]any{
			"recipient": "carol@kr0n.dev",
			"data": map[string]any{
				"org_name": "kr0n Corp",
				"role_id":  "admin",
				"token":    "tok_789",
			},
		},
		CreatedAt: now,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(enq.enqueued) != 3 {
		t.Fatalf("expected 3 enqueued messages, got %d", len(enq.enqueued))
	}

	if enq.enqueued[0].Type != email.TemplateVerifyEmail || enq.enqueued[0].Recipient != "alice@kr0n.dev" || enq.enqueued[0].Data["token"] != "tok_123" {
		t.Fatalf("unexpected verify job: %+v", enq.enqueued[0])
	}
	if enq.enqueued[1].Type != email.TemplatePasswordReset || enq.enqueued[1].Recipient != "bob@kr0n.dev" || enq.enqueued[1].Data["token"] != "tok_456" {
		t.Fatalf("unexpected reset job: %+v", enq.enqueued[1])
	}
	if enq.enqueued[2].Type != email.TemplateOrgInvite || enq.enqueued[2].Recipient != "carol@kr0n.dev" || enq.enqueued[2].Data["org_name"] != "kr0n Corp" {
		t.Fatalf("unexpected invite job: %+v", enq.enqueued[2])
	}
}
