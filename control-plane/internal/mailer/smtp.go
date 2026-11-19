package mailer

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/smtp"
	"os"
	"strings"
	"time"
)

// DefaultSMTPTimeout bounds how long a single SMTP connection + delivery attempt may take.
const DefaultSMTPTimeout = 5 * time.Second

// SMTPConfig configures an SMTPSender.
type SMTPConfig struct {
	Addr     string        // host:port, e.g. "localhost:1025" for Mailpit
	From     string        // sender address, e.g. "noreply@kr0n.dev"
	Username string        // optional SMTP auth username
	Password string        // optional SMTP auth password
	Timeout  time.Duration // maximum duration for dial + SMTP session; defaults to DefaultSMTPTimeout
}

// SMTPSender dispatches MIME emails over SMTP (net/smtp) with bounded context-aware
// dialing and explicit socket deadlines.
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

// DispatchMIME sends an email supporting Plain-Text only, HTML only, or multipart/alternative.
func (s *SMTPSender) DispatchMIME(ctx context.Context, recipient, subject, textBody, htmlBody string) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if strings.ContainsAny(recipient, "\r\n") || strings.ContainsAny(s.cfg.From, "\r\n") || strings.ContainsAny(subject, "\r\n") {
		return fmt.Errorf("mailer: header injection characters rejected")
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
