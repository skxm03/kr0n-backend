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
	s := NewInMemorySender()
	ctx := context.Background()

	if err := s.SendVerificationEmail(ctx, "user1@example.com", "token123"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	msgs := s.Messages()
	if len(msgs) != 1 {
		t.Fatalf("expected 1 message, got %d", len(msgs))
	}
	if msgs[0].Recipient != "user1@example.com" {
		t.Errorf("expected recipient user1@example.com, got %s", msgs[0].Recipient)
	}
	if msgs[0].RawToken != "token123" {
		t.Errorf("expected token token123, got %s", msgs[0].RawToken)
	}

	last, ok := s.LastMessage()
	if !ok || last.Recipient != "user1@example.com" {
		t.Errorf("expected last message to match, got ok=%v msg=%+v", ok, last)
	}

	// Test SetFailNext
	testErr := errors.New("simulated failure")
	s.SetFailNext(testErr)
	if err := s.SendVerificationEmail(ctx, "user2@example.com", "token456"); !errors.Is(err, testErr) {
		t.Fatalf("expected error %v, got %v", testErr, err)
	}

	// Next call should succeed
	if err := s.SendVerificationEmail(ctx, "user2@example.com", "token456"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Test Reset
	s.Reset()
	if len(s.Messages()) != 0 {
		t.Errorf("expected 0 messages after reset, got %d", len(s.Messages()))
	}
}

func TestLogSender_DoesNotLogRawToken(t *testing.T) {
	var buf bytes.Buffer
	logger := log.New(&buf, "", 0)
	sender := NewLogSender(logger)

	token := "sensitive_token_99999"
	err := sender.SendVerificationEmail(context.Background(), "user@example.com", token)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	logged := buf.String()
	if strings.Contains(logged, token) {
		t.Fatalf("CRITICAL SECURITY VIOLATION: raw token %q found in log: %s", token, logged)
	}
	if !strings.Contains(logged, "user@example.com") {
		t.Fatalf("expected recipient in log output: %s", logged)
	}
}
