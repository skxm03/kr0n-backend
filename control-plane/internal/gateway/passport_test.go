package gateway

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	authv1 "github.com/skxm03/kr0n-backend/control-plane/gen/auth/v1"
	"github.com/skxm03/kr0n-backend/control-plane/internal/gateway/middleware"
	"github.com/skxm03/kr0n-backend/control-plane/pkg/authz"
	"github.com/skxm03/kr0n-backend/control-plane/pkg/grpcauth"
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

func TestIncomingHeaderMatcher_BlocksPassportSpoofing(t *testing.T) {
	maliciousHeaders := []string{
		"Grpc-Metadata-X-Passport-User-Id",
		"GRPC-METADATA-X-PASSPORT-USER-ID",
		"grpc-metadata-x-passport-org-id",
		"grpc-metadata-x-passport-roles",
		"grpc-metadata-x-passport-permissions",
		"grpc-metadata-x-passport-kind",
		"grpc-metadata-x-passport-session-id",
		"X-Passport-User-Id",
		"x-passport-org-id",
		"x-passport-roles",
	}

	for _, hdr := range maliciousHeaders {
		t.Run(hdr, func(t *testing.T) {
			key, ok := IncomingHeaderMatcher(hdr)
			if ok {
				t.Fatalf("security violation: IncomingHeaderMatcher allowed spoofed passport header %q (mapped to %q)", hdr, key)
			}
		})
	}

	// Verify benign external headers pass normally
	allowedHeaders := map[string]string{
		"Grpc-Metadata-X-Request-Id":    "X-Request-Id",
		"Grpc-Metadata-Custom-Tracking": "Custom-Tracking",
	}
	for hdr, wantKey := range allowedHeaders {
		key, ok := IncomingHeaderMatcher(hdr)
		if !ok || key != wantKey {
			t.Fatalf("expected header %q to map to %q, got ok=%v, key=%q", hdr, wantKey, ok, key)
		}
	}
}

func TestPassport_UpstreamRejectsMissingPassport(t *testing.T) {
	// A request reaches an upstream service from a trusted service (mTLS verified),
	// but lacks any caller passport (e.g. unauthenticated public route forwarded upstream).
	cfg := grpcauth.ServiceAuthConfig{Enabled: true}
	trustedCtx := grpcauth.WithTrustedService(context.Background(), "kr0n-gateway")
	rawOrgID := uuid.New().String()

	// Missing both metadata passport and proto caller
	_, _, err := authz.ParseOrgCall(trustedCtx, cfg, nil, rawOrgID)
	if err == nil {
		t.Fatal("expected error for missing caller passport, got nil")
	}
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("expected codes.Unauthenticated, got %v", status.Code(err))
	}
	if status.Convert(err).Message() != "authentication required: missing caller passport" {
		t.Fatalf("unexpected error message: %v", err)
	}
}

func TestPassport_UpstreamRejectsUntrustedContextEvenWithMetadataPassport(t *testing.T) {
	// Attacker bypasses the gateway and connects directly to upstream gRPC port,
	// injecting X-Passport-* headers into gRPC metadata.
	// Because the connection lacks a valid mTLS client cert, the context is untrusted.
	cfg := grpcauth.ServiceAuthConfig{Enabled: true}
	untrustedCtx := context.Background()

	passportMD := metadata.Pairs(
		"x-passport-user-id", uuid.New().String(),
		"x-passport-kind", "session",
		"x-passport-org-id", uuid.New().String(),
		"x-passport-permissions", "org:admin",
	)
	metaCtx := metadata.NewIncomingContext(untrustedCtx, passportMD)

	_, _, err := authz.ParseOrgCall(metaCtx, cfg, nil, "")
	if err == nil {
		t.Fatal("expected untrusted service to be rejected even with passport headers")
	}
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("expected codes.Unauthenticated, got %v", status.Code(err))
	}
	if status.Convert(err).Message() != "caller principal rejected: untrusted service boundary" {
		t.Fatalf("unexpected error message: %v", err)
	}
}

func TestPassport_UpstreamAcceptsValidPassportFromTrustedService(t *testing.T) {
	cfg := grpcauth.ServiceAuthConfig{Enabled: true}
	trustedCtx := grpcauth.WithTrustedService(context.Background(), "kr0n-gateway")
	userID := uuid.New()
	orgID := uuid.New()

	passportMD := metadata.Pairs(
		"x-passport-user-id", userID.String(),
		"x-passport-kind", "session",
		"x-passport-org-id", orgID.String(),
		"x-passport-permissions", "project:read,project:update",
	)
	metaCtx := metadata.NewIncomingContext(trustedCtx, passportMD)

	p, parsedOrgID, err := authz.ParseOrgCall(metaCtx, cfg, nil, "")
	if err != nil {
		t.Fatalf("expected valid passport call to succeed, got %v", err)
	}
	if p.UserID != userID {
		t.Fatalf("expected user ID %v, got %v", userID, p.UserID)
	}
	if p.Kind != "session" {
		t.Fatalf("expected kind 'session', got %v", p.Kind)
	}
	if parsedOrgID != orgID {
		t.Fatalf("expected org ID %v, got %v", orgID, parsedOrgID)
	}
	if !authz.HasPermission(p.TokenPermissions, "project:read") || !authz.HasPermission(p.TokenPermissions, "project:update") {
		t.Fatalf("expected permissions project:read and project:update, got %v", p.TokenPermissions)
	}
	if authz.HasPermission(p.TokenPermissions, "project:delete") {
		t.Fatal("expected HasPermission('project:delete') to be false")
	}
}
