package audit

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	amqp "github.com/rabbitmq/amqp091-go"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type recordedPublish struct {
	Exchange   string
	RoutingKey string
	Msg        amqp.Publishing
}

type mockTransport struct {
	mu        sync.Mutex
	published []recordedPublish
	blockCh   chan struct{}
	failErr   error
	closed    bool
}

func (m *mockTransport) Publish(_ context.Context, exchange, routingKey string, msg amqp.Publishing) error {
	if m.blockCh != nil {
		<-m.blockCh
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failErr != nil {
		return m.failErr
	}
	m.published = append(m.published, recordedPublish{
		Exchange:   exchange,
		RoutingKey: routingKey,
		Msg:        msg,
	})
	return nil
}

func (m *mockTransport) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	return nil
}

func (m *mockTransport) Entries() []recordedPublish {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]recordedPublish, len(m.published))
	copy(out, m.published)
	return out
}

func TestEvent_NormalizeValidateAndRoutingKey(t *testing.T) {
	ev := Event{
		Action: " Org.Member.Invited ",
		Target: Target{
			Type: "invite",
			ID:   "inv-123",
		},
	}
	ev.Normalize("auth")

	if ev.ID == uuid.Nil {
		t.Fatal("expected non-nil event ID")
	}
	if ev.Version != SchemaVersion {
		t.Fatalf("expected version %q, got %q", SchemaVersion, ev.Version)
	}
	if ev.Service != "auth" {
		t.Fatalf("expected service 'auth', got %q", ev.Service)
	}
	if ev.Actor.Type != ActorTypeUser {
		t.Fatalf("expected default actor type %q, got %q", ActorTypeUser, ev.Actor.Type)
	}
	if ev.Status != StatusSuccess {
		t.Fatalf("expected default status %q, got %q", StatusSuccess, ev.Status)
	}
	if err := ev.Validate(); err != nil {
		t.Fatalf("expected valid event, got: %v", err)
	}

	gotKey := ev.RoutingKey("audit")
	wantKey := "audit.auth.org.member.invited"
	if gotKey != wantKey {
		t.Fatalf("routing key: got %q, want %q", gotKey, wantKey)
	}
}

func TestEvent_ValidationFailures(t *testing.T) {
	cases := []struct {
		name string
		ev   Event
		want error
	}{
		{
			name: "missing service",
			ev:   Event{Action: "user.login", Target: Target{Type: "user"}, Actor: Actor{Type: ActorTypeUser}},
			want: ErrMissingService,
		},
		{
			name: "missing action",
			ev:   Event{Service: "auth", Target: Target{Type: "user"}, Actor: Actor{Type: ActorTypeUser}},
			want: ErrMissingAction,
		},
		{
			name: "missing target type",
			ev:   Event{Service: "auth", Action: "user.login", Actor: Actor{Type: ActorTypeUser}},
			want: ErrMissingTargetType,
		},
		{
			name: "invalid actor type",
			ev:   Event{Service: "auth", Action: "user.login", Target: Target{Type: "user"}, Actor: Actor{Type: "hacker"}},
			want: ErrInvalidActorType,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.ev.Validate(); !errors.Is(err, tc.want) {
				t.Fatalf("got err %v, want %v", err, tc.want)
			}
		})
	}
}

func TestRabbitMQEmitter_AsyncAndDrainOnClose(t *testing.T) {
	tr := &mockTransport{}
	emitter, err := NewRabbitMQEmitter(EmitterConfig{
		ServiceName: "auth",
		BufferSize:  16,
		Workers:     2,
		Transport:   tr,
	})
	if err != nil {
		t.Fatalf("NewRabbitMQEmitter: %v", err)
	}

	orgID := uuid.New()
	actorID := uuid.New()
	for i := 0; i < 5; i++ {
		if err := emitter.Emit(context.Background(), Event{
			OrganizationID: &orgID,
			Action:         "apitoken.created",
			Actor:          Actor{UserID: &actorID, Type: ActorTypeUser},
			Target:         Target{Type: "api_token", ID: "tok-1"},
			Metadata:       map[string]any{"idx": i},
		}); err != nil {
			t.Fatalf("Emit(%d): %v", i, err)
		}
	}

	if err := emitter.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	entries := tr.Entries()
	if len(entries) != 5 {
		t.Fatalf("expected 5 published messages after Close drain, got %d", len(entries))
	}

	var decoded Event
	if err := json.Unmarshal(entries[0].Msg.Body, &decoded); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	if entries[0].RoutingKey != "audit.auth.apitoken.created" {
		t.Fatalf("unexpected routing key %q", entries[0].RoutingKey)
	}
	if decoded.OrganizationID == nil || *decoded.OrganizationID != orgID {
		t.Fatalf("unexpected decoded orgID: %+v", decoded.OrganizationID)
	}

	if err := emitter.Emit(context.Background(), Event{
		Action: "apitoken.created",
		Target: Target{Type: "api_token"},
	}); !errors.Is(err, ErrEmitterClosed) {
		t.Fatalf("expected ErrEmitterClosed after Close, got %v", err)
	}
}

func TestRabbitMQEmitter_FailOpenWhenBufferSaturated(t *testing.T) {
	blockCh := make(chan struct{})
	tr := &mockTransport{blockCh: blockCh}
	emitter, err := NewRabbitMQEmitter(EmitterConfig{
		ServiceName: "gateway",
		BufferSize:  1,
		Workers:     1,
		Transport:   tr,
	})
	if err != nil {
		t.Fatalf("NewRabbitMQEmitter: %v", err)
	}

	ev := Event{
		Action: "gateway.request",
		Target: Target{Type: "route", ID: "/api/v1/orgs"},
	}

	// Fill worker + buffer (1 in worker + 1 in buffer; 3rd must fail-open with ErrBufferFull immediately)
	_ = emitter.Emit(context.Background(), ev)
	time.Sleep(10 * time.Millisecond)
	_ = emitter.Emit(context.Background(), ev)

	err = emitter.Emit(context.Background(), ev)
	if !errors.Is(err, ErrBufferFull) {
		t.Fatalf("expected ErrBufferFull when saturated, got %v", err)
	}
	if emitter.DroppedCount() != 1 {
		t.Fatalf("expected dropped count 1, got %d", emitter.DroppedCount())
	}

	close(blockCh)
	_ = emitter.Close()
}

func TestHTTPMiddleware_And_GRPCUnaryInterceptor(t *testing.T) {
	mem := NewMemoryEmitter("gateway")
	orgID := uuid.New()

	mw := HTTPMiddleware(mem, HTTPMiddlewareConfig{
		ServiceName: "gateway",
		Extractor: func(_ *http.Request) RequestMetadata {
			return RequestMetadata{
				OrganizationID: &orgID,
				Action:         "gateway.proxy",
				Actor:          Actor{Type: ActorTypeAPIToken},
				Target:         Target{Type: "route", ID: "/api/v1/orgs"},
				ClientIP:       "203.0.113.10",
				RequestID:      "req-abc",
			}
		},
	})

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))

	req := httptest.NewRequest(http.MethodPost, "/api/v1/orgs", nil)
	req.Header.Set("User-Agent", "kr0n-cli/1.0")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	events := mem.Events()
	if len(events) != 1 {
		t.Fatalf("expected 1 HTTP audit event, got %d", len(events))
	}
	if events[0].Status != StatusDenied || events[0].ClientContext.RequestID != "req-abc" {
		t.Fatalf("unexpected HTTP event: %+v", events[0])
	}

	// Test gRPC unary interceptor
	ic := UnaryServerInterceptor(mem, "github", nil)
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs(
		"x-client-ip", "198.51.100.7",
		"x-user-agent", "grpc-go/1.84",
		"x-request-id", "grpc-req-1",
	))
	_, _ = ic(ctx, nil, &grpc.UnaryServerInfo{FullMethod: "/github.v1.GitHubService/GetRepoTree"}, func(_ context.Context, _ any) (any, error) {
		return nil, status.Error(codes.PermissionDenied, "denied")
	})

	events = mem.Events()
	if len(events) != 2 {
		t.Fatalf("expected 2 total audit events, got %d", len(events))
	}
	if events[1].Status != StatusDenied || events[1].Target.ID != "/github.v1.GitHubService/GetRepoTree" {
		t.Fatalf("unexpected gRPC audit event: %+v", events[1])
	}
}
