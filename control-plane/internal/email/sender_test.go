package email

import (
	"bytes"
	"context"
	"errors"
	"log"
	"strings"
	"testing"
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
