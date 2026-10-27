package email

import "time"

// TemplateType identifies which embedded email template to render.
type TemplateType string

const (
	TemplateVerifyEmail   TemplateType = "verify_email"
	TemplatePasswordReset TemplateType = "password_reset"
	TemplateOrgInvite     TemplateType = "org_invite"

	DefaultQueueName = "email.jobs"
)

// JobMessage is the JSON payload published to RabbitMQ for asynchronous batch email delivery.
type JobMessage struct {
	ID        string            `json:"id"`
	Type      TemplateType      `json:"type"`
	Recipient string            `json:"recipient"`
	Data      map[string]string `json:"data"`
	CreatedAt time.Time         `json:"created_at"`
}
