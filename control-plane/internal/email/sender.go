package email

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"
)

// SentMessage records email metadata and content dispatched via InMemorySender.
type SentMessage struct {
	Recipient string
	RawToken  string
	Body      string
	SentAt    time.Time
}

// InMemorySender captures verification emails in-memory for testing and development.
// It is thread-safe and never outputs raw tokens to standard logs.
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

// SendVerificationEmail records the email message and raw token in memory.
func (s *InMemorySender) SendVerificationEmail(ctx context.Context, recipient, rawToken string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.failNext != nil {
		err := s.failNext
		s.failNext = nil
		return err
	}

	body := fmt.Sprintf("Please verify your email using token: %s", rawToken)
	s.messages = append(s.messages, SentMessage{
		Recipient: recipient,
		RawToken:  rawToken,
		Body:      body,
		SentAt:    time.Now().UTC(),
	})

	return nil
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

// SendVerificationEmail emits a safe log entry without logging the raw token.
func (s *LogSender) SendVerificationEmail(ctx context.Context, recipient, rawToken string) error {
	msg := fmt.Sprintf("[email] verification email dispatched for recipient: %s (token omitted for security)", recipient)
	if s.logger != nil {
		s.logger.Println(msg)
	} else {
		log.Println(msg)
	}
	return nil
}
