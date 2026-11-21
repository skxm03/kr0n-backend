package sinks_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	amqp "github.com/rabbitmq/amqp091-go"

	"github.com/skxm03/kr0n-backend/control-plane/internal/audit"
	"github.com/skxm03/kr0n-backend/control-plane/internal/audit/sinks"
	"github.com/skxm03/kr0n-backend/control-plane/internal/auth/repository"
	"github.com/skxm03/kr0n-backend/control-plane/internal/testdb"
	pkgAudit "github.com/skxm03/kr0n-backend/control-plane/pkg/audit"
)

type spyAcknowledger struct {
	mu      sync.Mutex
	acked   []uint64
	nacked  []uint64
	requeue []bool
}

func (s *spyAcknowledger) Ack(tag uint64, _ bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.acked = append(s.acked, tag)
	return nil
}

func (s *spyAcknowledger) Nack(tag uint64, _ bool, requeue bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nacked = append(s.nacked, tag)
	s.requeue = append(s.requeue, requeue)
	return nil
}

func (s *spyAcknowledger) Reject(tag uint64, requeue bool) error {
	return s.Nack(tag, false, requeue)
}

type memSink struct {
	mu       sync.Mutex
	name     string
	events   []pkgAudit.Event
	failLeft int
	failErr  error
}

func (m *memSink) Name() string {
	if m.name == "" {
		return "memory"
	}
	return m.name
}

func (m *memSink) WriteBatch(_ context.Context, events []pkgAudit.Event) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failLeft > 0 {
		m.failLeft--
		return m.failErr
	}
	m.events = append(m.events, events...)
	return nil
}

func (m *memSink) Close() error { return nil }

func (m *memSink) Events() []pkgAudit.Event {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]pkgAudit.Event, len(m.events))
	copy(out, m.events)
	return out
}

func TestBatchProcessor_ValidPoisonAndRedaction(t *testing.T) {
	ackSpy := &spyAcknowledger{}
	sink := &memSink{
		failLeft: 1, // First attempt fails transiently, second succeeds via retry backoff
		failErr:  errors.New("temporary db timeout"),
	}

	bp := audit.NewBatchProcessor(
		sink,
		audit.BatchConfig{
			BatchSize:    3,
			BatchTimeout: 50 * time.Millisecond,
			MaxRetries:   2,
			RetryBackoff: 5 * time.Millisecond,
		},
		audit.RedactSensitiveMetadataTransformer(),
	)

	deliveries := make(chan amqp.Delivery, 10)

	validEv := pkgAudit.Event{
		Service: "auth",
		Action:  "user.login",
		Target:  pkgAudit.Target{Type: "user", ID: "u-1"},
		Metadata: map[string]any{
			"email":         "alice@example.com",
			"password":      "super-secret-password",
			"refresh_token": "tok-secret",
			"nested": map[string]any{
				"client_secret": "gh-secret",
				"safe_field":    "visible",
			},
		},
	}
	validBody, _ := json.Marshal(validEv)

	invalidEv := pkgAudit.Event{
		Service: "auth",
		Action:  "", // Missing action -> fails Validate()
		Target:  pkgAudit.Target{Type: "user"},
	}
	invalidBody, _ := json.Marshal(invalidEv)

	// 1. Valid event
	deliveries <- amqp.Delivery{Acknowledger: ackSpy, DeliveryTag: 1, Body: validBody}
	// 2. Malformed JSON poison pill
	deliveries <- amqp.Delivery{Acknowledger: ackSpy, DeliveryTag: 2, Body: []byte(`{malformed-json`)}
	// 3. Schema-invalid event
	deliveries <- amqp.Delivery{Acknowledger: ackSpy, DeliveryTag: 3, Body: invalidBody}
	close(deliveries)

	if err := bp.Run(context.Background(), deliveries); err != nil && !errors.Is(err, audit.ErrBrokerDisconnected) {
		t.Fatalf("BatchProcessor.Run: %v", err)
	}

	// Tag 1 must be Acked; Tags 2 and 3 must be Nacked with requeue=false (sent to DLQ)
	if len(ackSpy.acked) != 1 || ackSpy.acked[0] != 1 {
		t.Fatalf("expected delivery 1 to be acked, got %v", ackSpy.acked)
	}
	if len(ackSpy.nacked) != 2 || ackSpy.nacked[0] != 2 || ackSpy.nacked[1] != 3 {
		t.Fatalf("expected deliveries 2 and 3 to be nacked to DLQ, got %v", ackSpy.nacked)
	}
	for _, rq := range ackSpy.requeue {
		if rq {
			t.Fatal("expected poison deliveries to be nacked with requeue=false")
		}
	}

	persisted := sink.Events()
	if len(persisted) != 1 {
		t.Fatalf("expected 1 persisted event, got %d", len(persisted))
	}
	gotMeta := persisted[0].Metadata
	if gotMeta["password"] != "[REDACTED]" || gotMeta["refresh_token"] != "[REDACTED]" {
		t.Fatalf("expected top-level sensitive fields to be redacted, got %+v", gotMeta)
	}
	nested := gotMeta["nested"].(map[string]any)
	if nested["client_secret"] != "[REDACTED]" || nested["safe_field"] != "visible" {
		t.Fatalf("expected nested sensitive fields to be redacted, got %+v", nested)
	}
}

func TestMultiSink_And_LoggerSink(t *testing.T) {
	var logBuf bytes.Buffer
	logSink := sinks.NewLoggerSink(&logBuf)
	m1 := &memSink{name: "m1"}
	m2 := &memSink{name: "m2"}

	multi := sinks.NewMultiSink(logSink, m1, m2)

	ev := pkgAudit.Event{
		Service: "gateway",
		Action:  "route.accessed",
		Target:  pkgAudit.Target{Type: "route", ID: "/api/v1/orgs"},
	}
	ev.Normalize("gateway")

	if err := multi.WriteBatch(context.Background(), []pkgAudit.Event{ev}); err != nil {
		t.Fatalf("MultiSink.WriteBatch: %v", err)
	}

	if len(m1.Events()) != 1 || len(m2.Events()) != 1 {
		t.Fatalf("expected both memory sinks to receive 1 event")
	}
	if !bytes.Contains(logBuf.Bytes(), []byte(`"action":"route.accessed"`)) {
		t.Fatalf("expected LoggerSink output to contain action, got %s", logBuf.String())
	}
}

func TestTieredMultiSink_AuxiliaryFailureDoesNotFailBatch(t *testing.T) {
	primary := &memSink{name: "db"}
	auxiliary := &memSink{name: "logger", failLeft: 10, failErr: errors.New("logger write error")}

	tiered := sinks.NewTieredMultiSink([]audit.Sink{primary}, []audit.Sink{auxiliary})

	ev := pkgAudit.Event{
		Service: "auth",
		Action:  "user.login",
		Target:  pkgAudit.Target{Type: "user", ID: "u-123"},
	}
	ev.Normalize("auth")

	// Primary succeeds while auxiliary fails: WriteBatch MUST succeed (returns nil)
	err := tiered.WriteBatch(context.Background(), []pkgAudit.Event{ev})
	if err != nil {
		t.Fatalf("expected nil error when only auxiliary sink fails, got: %v", err)
	}

	if len(primary.Events()) != 1 {
		t.Fatalf("expected primary sink to have persisted 1 event, got %d", len(primary.Events()))
	}
}

func TestTieredMultiSink_PrimaryFailureFailsBatch(t *testing.T) {
	primary := &memSink{name: "db", failLeft: 10, failErr: errors.New("database timeout")}
	auxiliary := &memSink{name: "logger"}

	tiered := sinks.NewTieredMultiSink([]audit.Sink{primary}, []audit.Sink{auxiliary})

	ev := pkgAudit.Event{
		Service: "auth",
		Action:  "user.login",
		Target:  pkgAudit.Target{Type: "user", ID: "u-123"},
	}
	ev.Normalize("auth")

	// Primary fails: WriteBatch MUST return the primary error
	err := tiered.WriteBatch(context.Background(), []pkgAudit.Event{ev})
	if err == nil {
		t.Fatal("expected error when primary sink fails, got nil")
	}
}

func TestPostgresSink_BatchInsertAndIdempotency(t *testing.T) {
	pool := testdb.Pool(t)
	ctx := context.Background()

	orgID := uuid.New()
	if _, err := pool.Exec(ctx, "INSERT INTO organizations (id, name, slug) VALUES ($1, 'Audit Sink Org', $2)", orgID, orgID.String()); err != nil {
		t.Fatalf("insert test org: %v", err)
	}

	pgSink := sinks.NewPostgresSink(pool, false)
	defer pgSink.Close()

	ip := net.ParseIP("203.0.113.42")
	ua := "kr0n-test-agent/1.0"
	ev1 := pkgAudit.Event{
		ID:             uuid.New(),
		Service:        "auth",
		Action:         "apitoken.created",
		Status:         pkgAudit.StatusSuccess,
		OrganizationID: &orgID,
		Actor:          pkgAudit.Actor{Type: pkgAudit.ActorTypeUser},
		Target:         pkgAudit.Target{Type: "api_token", ID: "tok-1"},
		ClientContext: pkgAudit.ClientContext{
			IPAddress: &ip,
			UserAgent: &ua,
			RequestID: "req-999",
		},
		Metadata:  map[string]any{"scope": "org:read"},
		Timestamp: time.Now().UTC().Add(-time.Minute),
	}
	ev1.Normalize("auth")

	ev2 := pkgAudit.Event{
		ID:             uuid.New(),
		Service:        "github",
		Action:         "github.installation_connected",
		Status:         pkgAudit.StatusSuccess,
		OrganizationID: &orgID,
		Actor:          pkgAudit.Actor{Type: pkgAudit.ActorTypeSystem},
		Target:         pkgAudit.Target{Type: "github_installation", ID: "inst-77"},
		Timestamp:      time.Now().UTC(),
	}
	ev2.Normalize("github")

	// Write batch containing ev1, ev2, AND a duplicate of ev1 to verify ON CONFLICT (id) DO NOTHING
	if err := pgSink.WriteBatch(ctx, []pkgAudit.Event{ev1, ev2, ev1}); err != nil {
		t.Fatalf("PostgresSink.WriteBatch failed: %v", err)
	}

	// Re-deliver entire batch again (simulating RabbitMQ redelivery after worker crash)
	if err := pgSink.WriteBatch(ctx, []pkgAudit.Event{ev1, ev2}); err != nil {
		t.Fatalf("PostgresSink.WriteBatch redelivery failed: %v", err)
	}

	auditRepo := repository.NewPostgresAuditRepository(pool)
	stored, err := auditRepo.ListByOrg(ctx, orgID, "", 10, 0)
	if err != nil {
		t.Fatalf("ListByOrg: %v", err)
	}
	if len(stored) != 2 {
		t.Fatalf("expected exactly 2 deduplicated events in Postgres, got %d: %+v", len(stored), stored)
	}
	if stored[0].ID != ev2.ID || stored[1].ID != ev1.ID {
		t.Fatalf("unexpected event order: got [%s, %s], want [%s, %s]",
			stored[0].ID, stored[1].ID, ev2.ID, ev1.ID)
	}
	if stored[1].Metadata["service"] != "auth" || stored[1].Metadata["request_id"] != "req-999" {
		t.Fatalf("expected metadata enrichment with service and request_id, got %+v", stored[1].Metadata)
	}
}
