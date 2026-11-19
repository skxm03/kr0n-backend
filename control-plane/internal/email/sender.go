package email

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"
)

// Enqueuer defines an interface for publishers that enqueue email jobs to a message queue or test double.
type Enqueuer interface {
	Enqueue(ctx context.Context, job JobMessage) error
}

// SentMessage records email metadata and content dispatched via InMemorySender.
type SentMessage struct {
	Recipient string
	Subject   string
	RawToken  string
	Body      string
	SentAt    time.Time
}

// InMemorySender captures verification emails in-memory for testing and development.
// It is thread-safe and implements Enqueuer.
type InMemorySender struct {
	mu       sync.RWMutex
	messages []SentMessage
	failNext error
}

// NewInMemorySender creates a new in-memory email sender instance.
func NewInMemorySender() *InMemorySender {
	return &InMemorySender{
		messages: make([]SentMessage, 0),
	}
}

// Enqueue records an email job in memory.
func (s *InMemorySender) Enqueue(ctx context.Context, job JobMessage) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.failNext != nil {
		err := s.failNext
		s.failNext = nil
		return err
	}

	rawToken := ""
	if job.Data != nil {
		rawToken = job.Data["token"]
	}
	body := fmt.Sprintf("Email job %s for %s. Token: %s", job.Type, job.Recipient, rawToken)
	s.messages = append(s.messages, SentMessage{
		Recipient: job.Recipient,
		Subject:   string(job.Type),
		RawToken:  rawToken,
		Body:      body,
		SentAt:    job.CreatedAt,
	})

	return nil
}

// SendVerificationEmail records the verification email and raw token in memory.
func (s *InMemorySender) SendVerificationEmail(ctx context.Context, recipient, rawToken string) error {
	return s.Enqueue(ctx, JobMessage{
		Type:      TemplateVerifyEmail,
		Recipient: recipient,
		Data:      map[string]string{"token": rawToken},
		CreatedAt: time.Now().UTC(),
	})
}

// SendPasswordResetEmail records the password reset email and raw token in memory.
func (s *InMemorySender) SendPasswordResetEmail(ctx context.Context, recipient, rawToken string) error {
	return s.Enqueue(ctx, JobMessage{
		Type:      TemplatePasswordReset,
		Recipient: recipient,
		Data:      map[string]string{"token": rawToken},
		CreatedAt: time.Now().UTC(),
	})
}

// SendOrgInviteEmail records the organization invite email and raw token in memory.
func (s *InMemorySender) SendOrgInviteEmail(ctx context.Context, recipient, orgName, roleID, rawToken string) error {
	return s.Enqueue(ctx, JobMessage{
		Type:      TemplateOrgInvite,
		Recipient: recipient,
		Data: map[string]string{
			"org_name": orgName,
			"role_id":  roleID,
			"token":    rawToken,
		},
		CreatedAt: time.Now().UTC(),
	})
}

// SetFailNext instructs the sender to fail the next invocation with the provided error.
func (s *InMemorySender) SetFailNext(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failNext = err
}

// Messages returns a copy of all recorded messages.
func (s *InMemorySender) Messages() []SentMessage {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]SentMessage, len(s.messages))
	copy(out, s.messages)
	return out
}

// LastMessage returns the most recently sent message, if any.
func (s *InMemorySender) LastMessage() (SentMessage, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if len(s.messages) == 0 {
		return SentMessage{}, false
	}
	return s.messages[len(s.messages)-1], true
}

// Reset clears all recorded messages.
func (s *InMemorySender) Reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.messages = make([]SentMessage, 0)
	s.failNext = nil
}

// LogSender is an email adapter for development that logs safe audit messages
// without ever outputting the raw verification token.
type LogSender struct {
	logger *log.Logger
}

// NewLogSender creates a LogSender. If customLogger is nil, the standard logger is used.
func NewLogSender(customLogger *log.Logger) *LogSender {
	return &LogSender{
		logger: customLogger,
	}
}

// Enqueue logs the email job safely without logging raw token credentials.
func (s *LogSender) Enqueue(ctx context.Context, job JobMessage) error {
	msg := fmt.Sprintf("[email] job %s dispatched for recipient: %s type: %s (token omitted for security)", job.ID, job.Recipient, job.Type)
	if s.logger != nil {
		s.logger.Println(msg)
	} else {
		log.Println(msg)
	}
	return nil
}

// SendVerificationEmail emits a safe log entry without logging the raw token.
func (s *LogSender) SendVerificationEmail(ctx context.Context, recipient, rawToken string) error {
	return s.Enqueue(ctx, JobMessage{
		Type:      TemplateVerifyEmail,
		Recipient: recipient,
		Data:      map[string]string{"token": rawToken},
		CreatedAt: time.Now().UTC(),
	})
}

// SendPasswordResetEmail emits a safe log entry without logging the raw token.
func (s *LogSender) SendPasswordResetEmail(ctx context.Context, recipient, rawToken string) error {
	return s.Enqueue(ctx, JobMessage{
		Type:      TemplatePasswordReset,
		Recipient: recipient,
		Data:      map[string]string{"token": rawToken},
		CreatedAt: time.Now().UTC(),
	})
}

// SendOrgInviteEmail emits a safe log entry without logging the raw invite token.
func (s *LogSender) SendOrgInviteEmail(ctx context.Context, recipient, orgName, roleID, rawToken string) error {
	return s.Enqueue(ctx, JobMessage{
		Type:      TemplateOrgInvite,
		Recipient: recipient,
		Data: map[string]string{
			"org_name": orgName,
			"role_id":  roleID,
			"token":    rawToken,
		},
		CreatedAt: time.Now().UTC(),
	})
}
