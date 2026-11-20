package builtins_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/skxm03/kr0n-backend/control-plane/internal/auth/jwtkeys"
	"github.com/skxm03/kr0n-backend/control-plane/internal/gateway/middleware"
	"github.com/skxm03/kr0n-backend/control-plane/internal/gateway/middleware/builtins"
	pkgAudit "github.com/skxm03/kr0n-backend/control-plane/pkg/audit"
)

type stubTokenVerifier struct {
	claims *jwtkeys.Claims
	err    error
}

func (s stubTokenVerifier) VerifyContext(_ context.Context, _ string, _ time.Time) (*jwtkeys.Claims, error) {
	return s.claims, s.err
}

type stubPATVerifier struct {
	principal *middleware.Principal
	err       error
}

func (s stubPATVerifier) VerifyAPIToken(_ context.Context, _ string) (*middleware.Principal, error) {
	return s.principal, s.err
}

func TestAuditLogMiddleware_SessionAndOrgPathExtraction(t *testing.T) {
	emitter := pkgAudit.NewMemoryEmitter("gateway")
	userID := uuid.New()
	sessionID := uuid.New()
	orgID := uuid.New()

	deps := builtins.SharedDeps{
		AuditEmitter: emitter,
		Verifier: stubTokenVerifier{
			claims: &jwtkeys.Claims{
				Subject:   userID.String(),
				SessionID: sessionID.String(),
			},
		},
	}

	auditMW, err := builtins.NewAuditLogFactory(deps)(nil)
	if err != nil {
		t.Fatalf("NewAuditLogFactory: %v", err)
	}
	authMW, err := builtins.NewAuthenticationFactory(deps)(nil)
	if err != nil {
		t.Fatalf("NewAuthenticationFactory: %v", err)
	}

	// Build chain with audit_log BEFORE authentication (matching gateway.yaml profile ordering)
	r := chi.NewRouter()
	r.Method(http.MethodPost, "/api/v1/orgs/{org_id}/members", middleware.BuildHandler(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusCreated)
		}),
		[]middleware.Middleware{auditMW, authMW},
	))

	req := httptest.NewRequest(http.MethodPost, "/api/v1/orgs/"+orgID.String()+"/members", nil)
	req.RemoteAddr = "198.51.100.25:54321"
	req.Header.Set("Authorization", "Bearer valid-jwt")
	req.Header.Set("User-Agent", "kr0n-web/1.0")
	req.Header.Set("X-Request-ID", "req-gateway-1")

	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201 Created, got %d", rec.Code)
	}

	events := emitter.Events()
	if len(events) != 1 {
		t.Fatalf("expected 1 emitted audit event, got %d", len(events))
	}

	ev := events[0]
	if ev.Service != "gateway" || ev.Action != "gateway.http.post" || ev.Status != pkgAudit.StatusSuccess {
		t.Fatalf("unexpected event envelope: %+v", ev)
	}
	if ev.OrganizationID == nil || *ev.OrganizationID != orgID {
		t.Fatalf("expected orgID %s extracted from route param, got %v", orgID, ev.OrganizationID)
	}
	if ev.Actor.UserID == nil || *ev.Actor.UserID != userID || ev.Actor.Type != pkgAudit.ActorTypeUser {
		t.Fatalf("unexpected actor: %+v", ev.Actor)
	}
	if ev.ClientContext.RequestID != "req-gateway-1" || ev.ClientContext.IPAddress.String() != "198.51.100.25" {
		t.Fatalf("unexpected client context: %+v", ev.ClientContext)
	}
	if ev.Metadata["session_id"] != sessionID.String() || ev.Metadata["route_pattern"] != "/api/v1/orgs/{org_id}/members" {
		t.Fatalf("unexpected metadata: %+v", ev.Metadata)
	}
}

func TestAuditLogMiddleware_APITokenAndDeniedRequests(t *testing.T) {
	emitter := pkgAudit.NewMemoryEmitter("gateway")
	userID := uuid.New()
	orgID := uuid.New()

	deps := builtins.SharedDeps{
		AuditEmitter: emitter,
		APITokenVerifier: stubPATVerifier{
			principal: &middleware.Principal{
				UserID:  userID.String(),
				OrgID:   orgID.String(),
				TokenID: "tok-99",
				Kind:    middleware.PrincipalKindAPIToken,
			},
		},
	}

	auditMW, _ := builtins.NewAuditLogFactory(deps)(map[string]any{
		"action":      "github.repos.list",
		"target_type": "github_repository",
	})
	authMW, _ := builtins.NewAuthenticationFactory(deps)(map[string]any{
		"allow_api_tokens": true,
	})

	handler := middleware.BuildHandler(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		}),
		[]middleware.Middleware{auditMW, authMW},
	)

	// 1. Authorized API token call
	reqOK := httptest.NewRequest(http.MethodGet, "/api/v1/github/repos", nil)
	reqOK.Header.Set("Authorization", "Bearer kr0n_pat_valid")
	recOK := httptest.NewRecorder()
	handler.ServeHTTP(recOK, reqOK)

	// 2. Unauthorized call without Authorization header (rejected by authMW with 401)
	reqDenied := httptest.NewRequest(http.MethodGet, "/api/v1/orgs/"+orgID.String()+"/tokens", nil)
	recDenied := httptest.NewRecorder()
	handler.ServeHTTP(recDenied, reqDenied)

	// 3. OPTIONS preflight request (must be skipped)
	reqOpt := httptest.NewRequest(http.MethodOptions, "/api/v1/github/repos", nil)
	recOpt := httptest.NewRecorder()
	handler.ServeHTTP(recOpt, reqOpt)

	events := emitter.Events()
	if len(events) != 2 {
		t.Fatalf("expected 2 audit events (OPTIONS skipped), got %d", len(events))
	}

	// Verify API token event
	if events[0].Action != "github.repos.list" || events[0].Target.Type != "github_repository" {
		t.Fatalf("expected custom action and target_type, got %+v", events[0])
	}
	if events[0].Actor.Type != pkgAudit.ActorTypeAPIToken || events[0].Metadata["token_id"] != "tok-99" {
		t.Fatalf("expected api_token actor and token_id metadata, got %+v", events[0])
	}
	if events[0].OrganizationID == nil || *events[0].OrganizationID != orgID {
		t.Fatalf("expected orgID from PAT principal, got %v", events[0].OrganizationID)
	}

	// Verify Denied 401 event
	if events[1].Status != pkgAudit.StatusDenied || events[1].Metadata["status"] != http.StatusUnauthorized {
		t.Fatalf("expected denied status for 401 response, got %+v", events[1])
	}
	if events[1].OrganizationID == nil || *events[1].OrganizationID != orgID {
		t.Fatalf("expected orgID extracted from URL path on 401 request, got %v", events[1].OrganizationID)
	}
}
