package authz_test

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	authv1 "github.com/skxm03/kr0n-backend/control-plane/gen/auth/v1"
	"github.com/skxm03/kr0n-backend/control-plane/pkg/authz"
	"github.com/skxm03/kr0n-backend/control-plane/pkg/grpcauth"
)

type mockAuthorizer struct {
	allowed bool
}

func (m *mockAuthorizer) CheckPermission(_ context.Context, _ authz.Principal, _ uuid.UUID, _ string) (bool, error) {
	return m.allowed, nil
}

func TestCan_SessionAndAPITokenEvaluation(t *testing.T) {
	ctx := context.Background()
	orgA := uuid.New()
	orgB := uuid.New()
	userID := uuid.New()

	mockAuth := &mockAuthorizer{allowed: true}

	// 1. User Session allowed if authorizer allows
	sessPrincipal := authz.Principal{
		UserID: userID,
		Kind:   "session",
	}
	allowed, err := authz.Can(ctx, mockAuth, sessPrincipal, orgA, "project:create")
	if err != nil || !allowed {
		t.Fatalf("expected session allowed=true, got %v (err=%v)", allowed, err)
	}

	// Session denied if authorizer denies
	mockAuth.allowed = false
	allowed, err = authz.Can(ctx, mockAuth, sessPrincipal, orgA, "project:create")
	if err != nil || allowed {
		t.Fatalf("expected session allowed=false, got %v (err=%v)", allowed, err)
	}
	mockAuth.allowed = true

	// 2. API Token for orgA with project:create
	tokenPrincipal := authz.Principal{
		UserID:           userID,
		Kind:             "api_token",
		TokenOrgID:       &orgA,
		TokenPermissions: []string{"project:create", "project:read"},
	}
	allowed, err = authz.Can(ctx, mockAuth, tokenPrincipal, orgA, "project:create")
	if err != nil || !allowed {
		t.Fatalf("expected api_token allowed=true, got %v (err=%v)", allowed, err)
	}

	// API Token denied if permission not granted on token
	allowed, err = authz.Can(ctx, mockAuth, tokenPrincipal, orgA, "project:delete")
	if err != nil || allowed {
		t.Fatalf("expected api_token allowed=false for ungranted perm, got %v", allowed)
	}

	// API Token denied if used against another organization
	allowed, err = authz.Can(ctx, mockAuth, tokenPrincipal, orgB, "project:create")
	if err != nil || allowed {
		t.Fatalf("expected api_token allowed=false for mismatched org, got %v", allowed)
	}

	// 3. Nil IDs or empty permission always return false
	if ok, _ := authz.Can(ctx, mockAuth, authz.Principal{}, orgA, "project:create"); ok {
		t.Fatal("expected nil user ID to return false")
	}
	if ok, _ := authz.Can(ctx, mockAuth, sessPrincipal, uuid.Nil, "project:create"); ok {
		t.Fatal("expected nil org ID to return false")
	}
	if ok, _ := authz.Can(ctx, mockAuth, sessPrincipal, orgA, ""); ok {
		t.Fatal("expected empty permission to return false")
	}
}

func TestParseOrgCall_ServiceAuthAndPassport(t *testing.T) {
	ctx := context.Background()
	orgID := uuid.New()
	userID := uuid.New()

	cfg := grpcauth.ServiceAuthConfig{
		Enabled: true,
	}

	// 1. Untrusted context rejected
	_, _, err := authz.ParseOrgCall(ctx, cfg, &authv1.CallerPrincipal{UserId: userID.String()}, orgID.String())
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("expected Unauthenticated, got %v", err)
	}

	// 2. Trusted context with proto caller succeeds
	trustedCtx := grpcauth.WithTrustedService(ctx, "kr0n-gateway")
	p, oID, err := authz.ParseOrgCall(trustedCtx, cfg, &authv1.CallerPrincipal{
		UserId: userID.String(),
		Kind:   "session",
	}, orgID.String())
	if err != nil {
		t.Fatalf("ParseOrgCall failed: %v", err)
	}
	if p.UserID != userID || oID != orgID || p.Kind != "session" {
		t.Fatalf("unexpected parsed result: %+v, %s", p, oID)
	}

	// 3. Trusted context with metadata passport succeeds
	passportMD := metadata.Pairs(
		"x-passport-user-id", userID.String(),
		"x-passport-kind", "session",
		"x-passport-org-id", orgID.String(),
		"x-passport-permissions", "project:read,project:update",
	)
	metaCtx := metadata.NewIncomingContext(trustedCtx, passportMD)
	pMeta, oIDMeta, err := authz.ParseOrgCall(metaCtx, cfg, nil, "")
	if err != nil {
		t.Fatalf("ParseOrgCall with metadata failed: %v", err)
	}
	if pMeta.UserID != userID || oIDMeta != orgID || len(pMeta.TokenPermissions) != 2 {
		t.Fatalf("unexpected metadata parsed result: %+v, %s", pMeta, oIDMeta)
	}
}
