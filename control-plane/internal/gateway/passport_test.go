package gateway

import (
	"context"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	authv1 "github.com/skxm03/kr0n-backend/control-plane/gen/auth/v1"
	"github.com/skxm03/kr0n-backend/control-plane/internal/gateway/middleware"
)

func TestInjectPassport_Authenticated(t *testing.T) {
	principal := &middleware.Principal{
		UserID:      "018f3a5e-6c8a-7292-9111-bf74c2d67d71",
		Kind:        middleware.PrincipalKindSession,
		OrgID:       "018f3a5e-6c8a-7292-9111-bf74c2d67d72",
		Permissions: []string{"org:read", "members:write"},
		SessionID:   "018f3a5e-6c8a-7292-9111-bf74c2d67d73",
	}

	req := &authv1.GetMeRequest{}
	InjectPassport(req, principal)

	if req.GetCaller() == nil {
		t.Fatal("expected req.Caller to be populated, got nil")
	}
	if req.GetCaller().GetUserId() != principal.UserID {
		t.Fatalf("expected user_id %q, got %q", principal.UserID, req.GetCaller().GetUserId())
	}
	if req.GetCaller().GetKind() != principal.Kind {
		t.Fatalf("expected kind %q, got %q", principal.Kind, req.GetCaller().GetKind())
	}
	if req.GetCaller().GetTokenOrgId() != principal.OrgID {
		t.Fatalf("expected token_org_id %q, got %q", principal.OrgID, req.GetCaller().GetTokenOrgId())
	}
	if req.GetCaller().GetSessionId() != principal.SessionID {
		t.Fatalf("expected session_id %q, got %q", principal.SessionID, req.GetCaller().GetSessionId())
	}
	if len(req.GetCaller().GetTokenPermissions()) != 2 {
		t.Fatalf("expected 2 token permissions, got %v", req.GetCaller().GetTokenPermissions())
	}
}

func TestInjectPassport_ClearsUntrustedCallerWhenUnauthenticated(t *testing.T) {
	// Attacker injects a caller passport in raw HTTP JSON body
	req := &authv1.CreateOrganizationRequest{
		Caller: &authv1.CallerPrincipal{
			UserId: "spoofed-user-id",
		},
		Name: "Spoofed Corp",
		Slug: "spoofed-corp",
	}

	// No principal in context (unauthenticated)
	InjectPassport(req, nil)

	if req.GetCaller() != nil {
		t.Fatalf("expected spoofed caller to be cleared when unauthenticated, got %+v", req.GetCaller())
	}
}

func TestInjectPassport_OverwritesSpoofedCallerWhenAuthenticated(t *testing.T) {
	principal := &middleware.Principal{
		UserID:    "authenticated-user-id",
		Kind:      middleware.PrincipalKindSession,
		SessionID: "sess-123",
	}

	// Attacker tries to impersonate another user in the body
	req := &authv1.ChangePasswordRequest{
		Caller: &authv1.CallerPrincipal{
			UserId: "victim-user-id",
		},
		CurrentPassword: "old",
		NewPassword:     "new",
	}

	InjectPassport(req, principal)

	if req.GetCaller() == nil {
		t.Fatal("expected caller to be present")
	}
	if req.GetCaller().GetUserId() != "authenticated-user-id" {
		t.Fatalf("expected caller user_id to be overwritten with authenticated principal %q, got %q",
			principal.UserID, req.GetCaller().GetUserId())
	}
}

func TestInjectPassport_NoCallerFieldOnMessage(t *testing.T) {
	principal := &middleware.Principal{
		UserID: "some-user-id",
	}

	req := &authv1.LoginRequest{
		Email:    "test@example.com",
		Password: "password123",
	}

	// Should not panic or corrupt message
	InjectPassport(req, principal)
	if req.GetEmail() != "test@example.com" {
		t.Fatalf("unexpected modification to LoginRequest: %v", req)
	}
}

func TestPassportUnaryClientInterceptor(t *testing.T) {
	interceptor := PassportUnaryClientInterceptor()

	principal := &middleware.Principal{
		UserID:    "user-999",
		Kind:      "session",
		SessionID: "sess-999",
	}

	ctx := middleware.WithPrincipal(context.Background(), principal)
	req := &authv1.GetMeRequest{}

	invokerCalled := false
	invoker := func(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, opts ...grpc.CallOption) error {
		invokerCalled = true
		r, ok := req.(*authv1.GetMeRequest)
		if !ok {
			t.Fatal("expected *authv1.GetMeRequest")
		}
		if r.GetCaller() == nil || r.GetCaller().GetUserId() != "user-999" {
			t.Fatalf("expected caller passport to be injected before invoker, got: %+v", r.GetCaller())
		}
		md, ok := metadata.FromOutgoingContext(ctx)
		if !ok {
			t.Fatal("expected outgoing metadata to be present")
		}
		if len(md.Get("x-passport-user-id")) == 0 || md.Get("x-passport-user-id")[0] != "user-999" {
			t.Fatalf("expected x-passport-user-id metadata to be user-999, got: %v", md.Get("x-passport-user-id"))
		}
		return nil
	}

	err := interceptor(ctx, "/auth.v1.AuthService/GetMe", req, nil, nil, invoker)
	if err != nil {
		t.Fatalf("interceptor error: %v", err)
	}
	if !invokerCalled {
		t.Fatal("invoker was not called")
	}
}
