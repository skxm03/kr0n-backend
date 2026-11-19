package outbox

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/skxm03/kr0n-backend/control-plane/internal/auth/repository"
	"github.com/skxm03/kr0n-backend/control-plane/internal/email"
)

// Publisher dispatches an outbox event to an external transport or messaging system.
type Publisher interface {
	Publish(ctx context.Context, ev *repository.OutboxEvent) error
}

// EmailPublisher implements Publisher for email-related events by enqueueing them to an email.Enqueuer.
type EmailPublisher struct {
	enqueuer email.Enqueuer
}

// NewEmailPublisher creates an EmailPublisher wrapping an email.Enqueuer (e.g. RabbitMQSender or InMemorySender).
func NewEmailPublisher(enqueuer email.Enqueuer) *EmailPublisher {
	return &EmailPublisher{enqueuer: enqueuer}
}

// Publish transforms an OutboxEvent into an email delivery action.
func (p *EmailPublisher) Publish(ctx context.Context, ev *repository.OutboxEvent) error {
	if ev == nil {
		return nil
	}
	if p.enqueuer == nil {
		return fmt.Errorf("outbox: email enqueuer is not configured")
	}

	switch ev.EventType {
	case repository.EventTypeEmailVerification:
		return p.publishVerification(ctx, ev)
	case repository.EventTypePasswordReset:
		return p.publishPasswordReset(ctx, ev)
	case repository.EventTypeOrgInvite:
		return p.publishOrgInvite(ctx, ev)
	default:
		return fmt.Errorf("unsupported email outbox event type: %q", ev.EventType)
	}
}

func (p *EmailPublisher) publishVerification(ctx context.Context, ev *repository.OutboxEvent) error {
	recipient, _ := ev.Payload["recipient"].(string)
	data, _ := ev.Payload["data"].(map[string]any)
	token := ""
	if data != nil {
		token, _ = data["token"].(string)
	}
	if recipient == "" || token == "" {
		var job email.JobMessage
		bytes, err := json.Marshal(ev.Payload)
		if err == nil && json.Unmarshal(bytes, &job) == nil {
			recipient = job.Recipient
			if job.Data != nil {
				token = job.Data["token"]
			}
		}
	}
	if recipient == "" {
		return fmt.Errorf("outbox event %s missing email recipient", ev.ID)
	}

	job := email.JobMessage{
		ID:        ev.ID.String(),
		Type:      email.TemplateVerifyEmail,
		Recipient: recipient,
		Data: map[string]string{
			"token": token,
		},
		CreatedAt: ev.CreatedAt,
	}

	return p.enqueuer.Enqueue(ctx, job)
}

func (p *EmailPublisher) publishPasswordReset(ctx context.Context, ev *repository.OutboxEvent) error {
	recipient, _ := ev.Payload["recipient"].(string)
	data, _ := ev.Payload["data"].(map[string]any)
	token := ""
	if data != nil {
		token, _ = data["token"].(string)
	}
	if recipient == "" || token == "" {
		var job email.JobMessage
		bytes, err := json.Marshal(ev.Payload)
		if err == nil && json.Unmarshal(bytes, &job) == nil {
			recipient = job.Recipient
			if job.Data != nil {
				token = job.Data["token"]
			}
		}
	}
	if recipient == "" {
		return fmt.Errorf("outbox event %s missing password reset recipient", ev.ID)
	}

	job := email.JobMessage{
		ID:        ev.ID.String(),
		Type:      email.TemplatePasswordReset,
		Recipient: recipient,
		Data: map[string]string{
			"token": token,
		},
		CreatedAt: ev.CreatedAt,
	}

	return p.enqueuer.Enqueue(ctx, job)
}

func (p *EmailPublisher) publishOrgInvite(ctx context.Context, ev *repository.OutboxEvent) error {
	recipient, _ := ev.Payload["recipient"].(string)
	data, _ := ev.Payload["data"].(map[string]any)
	token := ""
	orgName := ""
	roleID := ""
	if data != nil {
		token, _ = data["token"].(string)
		orgName, _ = data["org_name"].(string)
		roleID, _ = data["role_id"].(string)
	}

	if recipient == "" || token == "" {
		var job email.JobMessage
		bytes, err := json.Marshal(ev.Payload)
		if err == nil && json.Unmarshal(bytes, &job) == nil {
			recipient = job.Recipient
			if job.Data != nil {
				token = job.Data["token"]
				orgName = job.Data["org_name"]
				roleID = job.Data["role_id"]
			}
		}
	}
	if recipient == "" {
		return fmt.Errorf("outbox event %s missing org invite recipient", ev.ID)
	}

	job := email.JobMessage{
		ID:        ev.ID.String(),
		Type:      email.TemplateOrgInvite,
		Recipient: recipient,
		Data: map[string]string{
			"org_name": orgName,
			"role_id":  roleID,
			"token":    token,
		},
		CreatedAt: ev.CreatedAt,
	}

	return p.enqueuer.Enqueue(ctx, job)
}
