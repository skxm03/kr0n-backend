package email

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/smtp"
	"os"
	"strings"
	"sync"
	"time"
)

// DefaultSMTPTimeout bounds how long a single SMTP connection + delivery attempt may take when
// neither SMTPConfig.Timeout nor the caller's context carries an earlier deadline.
const DefaultSMTPTimeout = 5 * time.Second

// SentMessage records email metadata and content dispatched via InMemorySender.
type SentMessage struct {
	Recipient string
	Subject   string
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
		Subject:   "Verify your kr0n email address",
		RawToken:  rawToken,
		Body:      body,
		SentAt:    time.Now().UTC(),
	})

	return nil
}

// SendPasswordResetEmail records the password reset email and raw token in memory.
func (s *InMemorySender) SendPasswordResetEmail(ctx context.Context, recipient, rawToken string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.failNext != nil {
		err := s.failNext
		s.failNext = nil
		return err
	}

	body := fmt.Sprintf("Reset your password using token: %s", rawToken)
	s.messages = append(s.messages, SentMessage{
		Recipient: recipient,
		Subject:   "Reset your kr0n password",
		RawToken:  rawToken,
		Body:      body,
		SentAt:    time.Now().UTC(),
	})

	return nil
}

// SendOrgInviteEmail records the organization invite email and raw token in memory.
func (s *InMemorySender) SendOrgInviteEmail(ctx context.Context, recipient, orgName, roleID, rawToken string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.failNext != nil {
		err := s.failNext
		s.failNext = nil
		return err
	}

	body := fmt.Sprintf("You have been invited to join %s as %s. Token: %s", orgName, roleID, rawToken)
	s.messages = append(s.messages, SentMessage{
		Recipient: recipient,
		Subject:   fmt.Sprintf("Invitation to join %s on kr0n", orgName),
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

// SendPasswordResetEmail emits a safe log entry without logging the raw token.
func (s *LogSender) SendPasswordResetEmail(ctx context.Context, recipient, rawToken string) error {
	msg := fmt.Sprintf("[email] password reset email dispatched for recipient: %s (token omitted for security)", recipient)
	if s.logger != nil {
		s.logger.Println(msg)
	} else {
		log.Println(msg)
	}
	return nil
}

// SendOrgInviteEmail emits a safe log entry without logging the raw invite token.
func (s *LogSender) SendOrgInviteEmail(ctx context.Context, recipient, orgName, roleID, rawToken string) error {
	msg := fmt.Sprintf("[email] organization invite email dispatched for recipient: %s org: %s role: %s (token omitted for security)", recipient, orgName, roleID)
	if s.logger != nil {
		s.logger.Println(msg)
	} else {
		log.Println(msg)
	}
	return nil
}

// SMTPConfig configures an SMTPSender.
type SMTPConfig struct {
	Addr     string        // host:port, e.g. "localhost:1025" for Mailpit
	From     string        // sender address, e.g. "noreply@kr0n.dev"
	Username string        // optional SMTP auth username
	Password string        // optional SMTP auth password
	Timeout  time.Duration // maximum duration for dial + SMTP session; defaults to DefaultSMTPTimeout
}

// SMTPSender dispatches plain-text transactional emails over SMTP (net/smtp) with bounded
// context-aware dialing and explicit socket deadlines.
//
// Architectural note on outbox_events: The database schema includes an outbox_events table for
// future asynchronous event/email relay. In the current control-plane scope, emails are dispatched
// synchronously with strict timeouts after the DB transaction commits so that transient SMTP faults
// never roll back user state or stall request goroutines.
type SMTPSender struct {
	cfg  SMTPConfig
	send func(ctx context.Context, addr string, a smtp.Auth, from string, to []string, msg []byte) error
	dial func(ctx context.Context, network, addr string) (net.Conn, error)
}

// NewSMTPSender creates an SMTPSender with bounded connection and I/O deadlines.
func NewSMTPSender(cfg SMTPConfig) *SMTPSender {
	if strings.TrimSpace(cfg.From) == "" {
		cfg.From = "noreply@kr0n.dev"
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = DefaultSMTPTimeout
	}
	s := &SMTPSender{cfg: cfg}
	s.send = s.sendMailWithContext
	return s
}

// SendVerificationEmail sends a plain-text verification email via SMTP.
func (s *SMTPSender) SendVerificationEmail(ctx context.Context, recipient, rawToken string) error {
	subject := "Verify your kr0n email address"
	body := fmt.Sprintf("Welcome to kr0n!\r\n\r\nPlease verify your email address using the following token:\r\n\r\n%s\r\n\r\nIf you did not request this, you can safely ignore this email.\r\n", rawToken)
	return s.dispatch(ctx, recipient, subject, body)
}

// SendPasswordResetEmail sends a plain-text password reset email via SMTP.
func (s *SMTPSender) SendPasswordResetEmail(ctx context.Context, recipient, rawToken string) error {
	subject := "Reset your kr0n password"
	body := fmt.Sprintf("A password reset was requested for your kr0n account.\r\n\r\nUse the following token to reset your password:\r\n\r\n%s\r\n\r\nIf you did not request this, you can safely ignore this email.\r\n", rawToken)
	return s.dispatch(ctx, recipient, subject, body)
}

// SendOrgInviteEmail sends a plain-text organization invitation email via SMTP.
func (s *SMTPSender) SendOrgInviteEmail(ctx context.Context, recipient, orgName, roleID, rawToken string) error {
	subject := fmt.Sprintf("Invitation to join %s on kr0n", orgName)
	body := fmt.Sprintf("You have been invited to join %s on kr0n with role %q.\r\n\r\nUse the following invitation token to accept:\r\n\r\n%s\r\n\r\nIf you did not expect this invitation, you can safely ignore this email.\r\n", orgName, roleID, rawToken)
	return s.dispatch(ctx, recipient, subject, body)
}

func (s *SMTPSender) dispatch(ctx context.Context, recipient, subject, body string) error {
	return s.DispatchMIME(ctx, recipient, subject, body, "")
}

// DispatchMIME sends an email supporting Plain-Text only, HTML only, or both (multipart/alternative).
func (s *SMTPSender) DispatchMIME(ctx context.Context, recipient, subject, textBody, htmlBody string) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if strings.ContainsAny(recipient, "\r\n") || strings.ContainsAny(s.cfg.From, "\r\n") || strings.ContainsAny(subject, "\r\n") {
		return fmt.Errorf("email: header injection characters rejected")
	}

	var auth smtp.Auth
	if s.cfg.Username != "" {
		host := smtpHost(s.cfg.Addr)
		auth = smtp.PlainAuth("", s.cfg.Username, s.cfg.Password, host)
	}

	var raw string
	switch {
	case textBody != "" && htmlBody != "":
		const boundary = "kr0n-mime-boundary-9f8e7d6c5b4a"
		raw = fmt.Sprintf(
			"From: %s\r\nTo: %s\r\nSubject: %s\r\nMIME-Version: 1.0\r\nContent-Type: multipart/alternative; boundary=%q\r\n\r\n"+
				"--%s\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n%s\r\n"+
				"--%s\r\nContent-Type: text/html; charset=UTF-8\r\n\r\n%s\r\n"+
				"--%s--\r\n",
			s.cfg.From, recipient, subject, boundary,
			boundary, textBody,
			boundary, htmlBody,
			boundary,
		)
	case htmlBody != "":
		raw = fmt.Sprintf(
			"From: %s\r\nTo: %s\r\nSubject: %s\r\nMIME-Version: 1.0\r\nContent-Type: text/html; charset=UTF-8\r\n\r\n%s",
			s.cfg.From, recipient, subject, htmlBody,
		)
	default:
		raw = fmt.Sprintf(
			"From: %s\r\nTo: %s\r\nSubject: %s\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n%s",
			s.cfg.From, recipient, subject, textBody,
		)
	}
	return s.send(ctx, s.cfg.Addr, auth, s.cfg.From, []string{recipient}, []byte(raw))
}

func (s *SMTPSender) sendMailWithContext(ctx context.Context, addr string, a smtp.Auth, from string, to []string, msg []byte) error {
	timeout := s.cfg.Timeout
	if timeout <= 0 {
		timeout = DefaultSMTPTimeout
	}
	sendCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	deadline, _ := sendCtx.Deadline()
	dialFn := s.dial
	if dialFn == nil {
		dialer := net.Dialer{Deadline: deadline}
		dialFn = dialer.DialContext
	}
	conn, err := dialFn(sendCtx, "tcp", addr)
	if err != nil {
		if ctxErr := sendCtx.Err(); ctxErr != nil {
			return fmt.Errorf("smtp dial: %w", ctxErr)
		}
		return fmt.Errorf("smtp dial: %w", err)
	}

	if err := conn.SetDeadline(deadline); err != nil {
		_ = conn.Close()
		return fmt.Errorf("smtp set deadline: %w", err)
	}

	// Abort in-flight socket reads/writes immediately if the caller cancels sendCtx before deadline.
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-sendCtx.Done():
			_ = conn.SetDeadline(time.Now())
			_ = conn.Close()
		case <-done:
		}
	}()

	wrapErr := func(step string, err error) error {
		if ctxErr := sendCtx.Err(); ctxErr != nil {
			return fmt.Errorf("smtp %s: %w", step, ctxErr)
		}
		if errors.Is(err, os.ErrDeadlineExceeded) {
			return fmt.Errorf("smtp %s: %w: %v", step, context.DeadlineExceeded, err)
		}
		return fmt.Errorf("smtp %s: %w", step, err)
	}

	host := smtpHost(addr)
	client, err := smtp.NewClient(conn, host)
	if err != nil {
		_ = conn.Close()
		return wrapErr("greeting", err)
	}
	defer func() {
		_ = client.Close()
	}()

	if a != nil {
		if ok, _ := client.Extension("AUTH"); ok {
			if err := client.Auth(a); err != nil {
				return wrapErr("auth", err)
			}
		}
	}
	if err := client.Mail(from); err != nil {
		return wrapErr("mail from", err)
	}
	for _, rcpt := range to {
		if err := client.Rcpt(rcpt); err != nil {
			return wrapErr("rcpt to", err)
		}
	}
	w, err := client.Data()
	if err != nil {
		return wrapErr("data", err)
	}
	if _, err := w.Write(msg); err != nil {
		_ = w.Close()
		return wrapErr("write body", err)
	}
	if err := w.Close(); err != nil {
		return wrapErr("close data", err)
	}
	_ = client.Quit()
	return nil
}

func smtpHost(addr string) string {
	if h, _, err := net.SplitHostPort(addr); err == nil && h != "" {
		return h
	}
	if idx := strings.IndexByte(addr, ':'); idx != -1 {
		return addr[:idx]
	}
	return addr
}
