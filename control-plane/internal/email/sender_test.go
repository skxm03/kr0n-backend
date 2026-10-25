package email

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"log"
	"net"
	"net/smtp"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestInMemorySender(t *testing.T) {
	ctx := context.Background()
	sender := NewInMemorySender()

	recipient := "user@kr0n.dev"
	rawToken := "5f2d9a8c1e3b7a4d9f2e8c1b7a4d9f2e8c1b7a4d9f2e8c1b7a4d9f2e8c1b7a4d"

	if err := sender.SendVerificationEmail(ctx, recipient, rawToken); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	msgs := sender.Messages()
	if len(msgs) != 1 {
		t.Fatalf("expected 1 message, got %d", len(msgs))
	}

	msg, ok := sender.LastMessage()
	if !ok {
		t.Fatal("expected last message to exist")
	}

	if msg.Recipient != recipient {
		t.Fatalf("expected recipient %q, got %q", recipient, msg.Recipient)
	}
	if msg.RawToken != rawToken {
		t.Fatalf("expected raw token %q, got %q", rawToken, msg.RawToken)
	}
	if !strings.Contains(msg.Body, rawToken) {
		t.Fatalf("expected email body to contain verification token, got %q", msg.Body)
	}

	// Test error injection
	simulatedErr := errors.New("smtp connection failed")
	sender.SetFailNext(simulatedErr)

	if err := sender.SendVerificationEmail(ctx, recipient, rawToken); !errors.Is(err, simulatedErr) {
		t.Fatalf("expected simulated error %v, got %v", simulatedErr, err)
	}

	// Verify next call succeeds after failNext consumed
	if err := sender.SendVerificationEmail(ctx, recipient, rawToken); err != nil {
		t.Fatalf("expected subsequent call to succeed, got %v", err)
	}

	// Test Reset
	sender.Reset()
	if len(sender.Messages()) != 0 {
		t.Fatal("expected messages to be empty after reset")
	}
}

func TestLogSender_DoesNotLogRawToken(t *testing.T) {
	ctx := context.Background()
	var buf bytes.Buffer
	customLogger := log.New(&buf, "", 0)

	sender := NewLogSender(customLogger)

	recipient := "sensitive_user@kr0n.dev"
	secretRawToken := "secret_token_never_to_be_logged_1234567890abcdef"

	if err := sender.SendVerificationEmail(ctx, recipient, secretRawToken); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	loggedOutput := buf.String()
	if !strings.Contains(loggedOutput, recipient) {
		t.Fatalf("expected log to mention recipient, got %q", loggedOutput)
	}
	if strings.Contains(loggedOutput, secretRawToken) {
		t.Fatalf("CRITICAL SECURITY VIOLATION: raw verification token was written to log output: %q", loggedOutput)
	}
}

func TestSMTPSender(t *testing.T) {
	ctx := context.Background()
	var (
		capturedAddr string
		capturedFrom string
		capturedTo   []string
		capturedMsg  string
	)

	sender := NewSMTPSender(SMTPConfig{
		Addr: "localhost:1025",
		From: "security@kr0n.dev",
	})
	sender.send = func(_ context.Context, addr string, _ smtp.Auth, from string, to []string, msg []byte) error {
		capturedAddr = addr
		capturedFrom = from
		capturedTo = to
		capturedMsg = string(msg)
		return nil
	}

	if err := sender.SendVerificationEmail(ctx, "alice@kr0n.dev", "verif-tok-123"); err != nil {
		t.Fatalf("SendVerificationEmail: %v", err)
	}
	if capturedAddr != "localhost:1025" || capturedFrom != "security@kr0n.dev" || len(capturedTo) != 1 || capturedTo[0] != "alice@kr0n.dev" {
		t.Fatalf("unexpected smtp params: addr=%q from=%q to=%v", capturedAddr, capturedFrom, capturedTo)
	}
	if !strings.Contains(capturedMsg, "verif-tok-123") || !strings.Contains(capturedMsg, "Subject: Verify your kr0n email address") {
		t.Fatalf("unexpected message: %s", capturedMsg)
	}

	if err := sender.SendPasswordResetEmail(ctx, "alice@kr0n.dev", "reset-tok-456"); err != nil {
		t.Fatalf("SendPasswordResetEmail: %v", err)
	}
	if !strings.Contains(capturedMsg, "reset-tok-456") || !strings.Contains(capturedMsg, "Subject: Reset your kr0n password") {
		t.Fatalf("unexpected reset message: %s", capturedMsg)
	}

	// Reject CRLF header injection
	if err := sender.SendVerificationEmail(ctx, "alice@kr0n.dev\r\nBcc: attacker@evil.com", "tok"); err == nil {
		t.Fatal("expected header injection to be rejected")
	}
}

type pipeListener struct {
	ch     chan net.Conn
	closed chan struct{}
}

func newPipeListener() *pipeListener {
	return &pipeListener{
		ch:     make(chan net.Conn),
		closed: make(chan struct{}),
	}
}

func (l *pipeListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.ch:
		return c, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

func (l *pipeListener) Close() error {
	select {
	case <-l.closed:
	default:
		close(l.closed)
	}
	return nil
}

func (l *pipeListener) Addr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 2525}
}

func (l *pipeListener) dial(ctx context.Context, _, _ string) (net.Conn, error) {
	c1, c2 := net.Pipe()
	select {
	case <-l.closed:
		_ = c1.Close()
		_ = c2.Close()
		return nil, errors.New("connect: connection refused")
	case <-ctx.Done():
		_ = c1.Close()
		_ = c2.Close()
		return nil, ctx.Err()
	case l.ch <- c2:
		return c1, nil
	}
}

func listenFakeSMTP(t *testing.T) (net.Listener, func(ctx context.Context, network, addr string) (net.Conn, error)) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err == nil {
		probeDone := make(chan struct{})
		go func() {
			defer close(probeDone)
			if c, err := ln.Accept(); err == nil {
				_ = c.Close()
			}
		}()
		if c, dialErr := net.DialTimeout("tcp", ln.Addr().String(), 100*time.Millisecond); dialErr == nil {
			_ = c.Close()
			<-probeDone
			return ln, nil
		}
		_ = ln.Close()
		<-probeDone
	}
	pl := newPipeListener()
	return pl, pl.dial
}

func TestSMTPSender_NetworkTimeoutsErrorsAndNoLeaks(t *testing.T) {
	baseGoroutines := runtime.NumGoroutine()

	// 1. Connection refused (closed local port)
	closedLn, closedDial := listenFakeSMTP(t)
	closedAddr := closedLn.Addr().String()
	_ = closedLn.Close()

	refusedSender := NewSMTPSender(SMTPConfig{Addr: closedAddr, From: "noreply@kr0n.dev", Timeout: 200 * time.Millisecond})
	refusedSender.dial = closedDial
	start := time.Now()
	if err := refusedSender.SendVerificationEmail(context.Background(), "alice@kr0n.dev", "tok"); err == nil {
		t.Fatal("expected error on connection refused")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("connection refused took too long: %v", elapsed)
	}

	// 2. Slow greeting / silent server stall before greeting (bounded by Timeout)
	stallLn, stallDial := listenFakeSMTP(t)
	defer stallLn.Close()
	go func() {
		for {
			c, err := stallLn.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_, _ = io.Copy(io.Discard, conn)
			}(c)
		}
	}()

	stallSender := NewSMTPSender(SMTPConfig{Addr: stallLn.Addr().String(), From: "noreply@kr0n.dev", Timeout: 120 * time.Millisecond})
	stallSender.dial = stallDial
	start = time.Now()
	err := stallSender.SendVerificationEmail(context.Background(), "alice@kr0n.dev", "tok")
	if err == nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected context.DeadlineExceeded on slow greeting, got %v", err)
	}
	if elapsed := time.Since(start); elapsed > 1500*time.Millisecond {
		t.Fatalf("slow greeting timeout took too long: %v", elapsed)
	}

	// 3. Server stalls mid-protocol after EHLO / MAIL FROM (bounded by Timeout)
	midStallLn, midStallDial := listenFakeSMTP(t)
	defer midStallLn.Close()
	go func() {
		for {
			c, err := midStallLn.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_, _ = conn.Write([]byte("220 fake.smtp ESMTP\r\n"))
				r := bufio.NewReader(conn)
				_, _ = r.ReadString('\n') // EHLO
				_, _ = conn.Write([]byte("250-fake.smtp\r\n250 OK\r\n"))
				_, _ = r.ReadString('\n') // MAIL FROM -> stall without replying!
				_, _ = io.Copy(io.Discard, conn)
			}(c)
		}
	}()

	midStallSender := NewSMTPSender(SMTPConfig{Addr: midStallLn.Addr().String(), From: "noreply@kr0n.dev", Timeout: 120 * time.Millisecond})
	midStallSender.dial = midStallDial
	start = time.Now()
	err = midStallSender.SendPasswordResetEmail(context.Background(), "alice@kr0n.dev", "tok")
	if err == nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected context.DeadlineExceeded on mid-protocol stall, got %v", err)
	}
	if elapsed := time.Since(start); elapsed > 1500*time.Millisecond {
		t.Fatalf("mid-protocol stall took too long: %v", elapsed)
	}

	// 4. Caller context cancellation aborts in-flight SMTP wait immediately
	cancelCtx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(40 * time.Millisecond)
		cancel()
	}()
	longSender := NewSMTPSender(SMTPConfig{Addr: stallLn.Addr().String(), From: "noreply@kr0n.dev", Timeout: 5 * time.Second})
	longSender.dial = stallDial
	start = time.Now()
	err = longSender.SendVerificationEmail(cancelCtx, "alice@kr0n.dev", "tok")
	if err == nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
	if elapsed := time.Since(start); elapsed > 1500*time.Millisecond {
		t.Fatalf("context cancellation took too long: %v", elapsed)
	}

	// 5. SMTP error response (e.g. 550 Mailbox unavailable on RCPT TO)
	errLn, errDial := listenFakeSMTP(t)
	defer errLn.Close()
	go func() {
		for {
			c, err := errLn.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_, _ = conn.Write([]byte("220 fake.smtp ESMTP\r\n"))
				r := bufio.NewReader(conn)
				_, _ = r.ReadString('\n') // EHLO
				_, _ = conn.Write([]byte("250 OK\r\n"))
				_, _ = r.ReadString('\n') // MAIL FROM
				_, _ = conn.Write([]byte("250 OK\r\n"))
				_, _ = r.ReadString('\n') // RCPT TO
				_, _ = conn.Write([]byte("550 5.1.1 Mailbox unavailable\r\n"))
			}(c)
		}
	}()

	errSender := NewSMTPSender(SMTPConfig{Addr: errLn.Addr().String(), From: "noreply@kr0n.dev", Timeout: time.Second})
	errSender.dial = errDial
	if err := errSender.SendVerificationEmail(context.Background(), "alice@kr0n.dev", "tok"); err == nil || !strings.Contains(err.Error(), "550") {
		t.Fatalf("expected 550 SMTP error, got %v", err)
	}

	// 6. Successful end-to-end SMTP delivery against local fake SMTP server
	okLn, okDial := listenFakeSMTP(t)
	defer okLn.Close()
	receivedCh := make(chan string, 1)
	go func() {
		c, err := okLn.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		_, _ = c.Write([]byte("220 fake.smtp ESMTP\r\n"))
		r := bufio.NewReader(c)
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			cmd := strings.ToUpper(strings.TrimSpace(line))
			switch {
			case strings.HasPrefix(cmd, "EHLO"), strings.HasPrefix(cmd, "HELO"), strings.HasPrefix(cmd, "MAIL FROM:"), strings.HasPrefix(cmd, "RCPT TO:"):
				_, _ = c.Write([]byte("250 OK\r\n"))
			case cmd == "DATA":
				_, _ = c.Write([]byte("354 End data with <CR><LF>.<CR><LF>\r\n"))
				var data strings.Builder
				for {
					dl, err := r.ReadString('\n')
					if err != nil || dl == ".\r\n" || dl == ".\n" {
						break
					}
					data.WriteString(dl)
				}
				receivedCh <- data.String()
				_, _ = c.Write([]byte("250 2.0.0 Queued\r\n"))
			case cmd == "QUIT":
				_, _ = c.Write([]byte("221 Bye\r\n"))
				return
			default:
				_, _ = c.Write([]byte("250 OK\r\n"))
			}
		}
	}()

	okSender := NewSMTPSender(SMTPConfig{Addr: okLn.Addr().String(), From: "noreply@kr0n.dev", Timeout: 2 * time.Second})
	okSender.dial = okDial
	if err := okSender.SendVerificationEmail(context.Background(), "alice@kr0n.dev", "tok-xyz-987"); err != nil {
		t.Fatalf("expected successful SMTP send, got %v", err)
	}
	select {
	case body := <-receivedCh:
		if !strings.Contains(body, "tok-xyz-987") || !strings.Contains(body, "To: alice@kr0n.dev") {
			t.Fatalf("unexpected received SMTP payload: %q", body)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for fake SMTP server to receive message")
	}

	// Verify no goroutine leaks after all failure/success paths settle
	time.Sleep(30 * time.Millisecond)
	if after := runtime.NumGoroutine(); after > baseGoroutines+6 {
		t.Fatalf("possible goroutine leak: before=%d after=%d", baseGoroutines, after)
	}
}
