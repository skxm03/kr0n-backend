package gateway

import (
	"context"
	"crypto/ed25519"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	authv1 "github.com/skxm03/kr0n-backend/control-plane/gen/auth/v1"
	"github.com/skxm03/kr0n-backend/control-plane/internal/auth/jwtkeys"
	"github.com/skxm03/kr0n-backend/control-plane/internal/gateway/ratelimit"
)

type fakeLimiter struct {
	res ratelimit.Result
	err error
}

func (f fakeLimiter) Allow(context.Context, string) (ratelimit.Result, error) { return f.res, f.err }

var allow = fakeLimiter{res: ratelimit.Result{Allowed: true, Limit: 10, Remaining: 9}}

func testServer(t *testing.T, general, auth ratelimit.Limiter) (http.Handler, *jwtkeys.Signer) {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(nil)
	signer, _ := jwtkeys.NewSigner(priv, "k1", "iss", "aud", time.Minute)
	verifier, _ := jwtkeys.NewVerifier(map[string]ed25519.PublicKey{"k1": pub}, "iss", "aud")
	h := NewHandler(&mockAuthClient{})
	return NewServerHandler(h, Options{
		Log:            slog.New(slog.NewTextHandler(io.Discard, nil)),
		Verifier:       verifier,
		GeneralLimiter: general,
		AuthLimiter:    auth,
	}), signer
}

func do(h http.Handler, method, path, authz string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(""))
	if authz != "" {
		req.Header.Set("Authorization", authz)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestMeRequiresValidBearer(t *testing.T) {
	h, signer := testServer(t, allow, allow)

	if rec := do(h, "GET", "/api/v1/me", ""); rec.Code != 401 {
		t.Fatalf("no token: %d", rec.Code)
	}
	if rec := do(h, "GET", "/api/v1/me", "Bearer garbage"); rec.Code != 401 {
		t.Fatalf("bad token: %d", rec.Code)
	}
	tok, _, _ := signer.Sign(uuid.New(), uuid.New(), time.Now())
	rec := do(h, "GET", "/api/v1/me", "Bearer "+tok)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "user_id") {
		t.Fatalf("valid token: %d %s", rec.Code, rec.Body)
	}
	if rec.Header().Get("X-Request-ID") == "" || rec.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatal("missing request id / security headers")
	}
}

func TestRateLimitedReturns429WithRetryAfter(t *testing.T) {
	deny := fakeLimiter{res: ratelimit.Result{Allowed: false, Limit: 5, RetryAfter: 1500 * time.Millisecond}}
	h, _ := testServer(t, allow, deny)
	rec := do(h, "POST", "/api/v1/auth/login", "")
	if rec.Code != 429 || rec.Header().Get("Retry-After") != "2" {
		t.Fatalf("got %d retry-after=%q", rec.Code, rec.Header().Get("Retry-After"))
	}
}

func TestLimiterOutageFailOpenGeneralFailClosedAuth(t *testing.T) {
	broken := fakeLimiter{err: errors.New("redis down")}
	h, _ := testServer(t, broken, broken)

	if rec := do(h, "GET", "/healthz", ""); rec.Code != 200 {
		t.Fatalf("general route should fail open, got %d", rec.Code)
	}
	if rec := do(h, "POST", "/api/v1/auth/login", ""); rec.Code != 503 {
		t.Fatalf("auth route should fail closed, got %d", rec.Code)
	}
}

func TestReadyz(t *testing.T) {
	h := NewServerHandler(NewHandler(&mockAuthClient{}), Options{
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)), GeneralLimiter: allow, AuthLimiter: allow,
		Ready: func(context.Context) error { return errors.New("down") },
	})
	if rec := do(h, "GET", "/readyz", ""); rec.Code != 503 {
		t.Fatalf("got %d", rec.Code)
	}
}

func TestHandlerErrorsCarryRequestID(t *testing.T) {
	h, _ := testServer(t, allow, allow)
	req := httptest.NewRequest("POST", "/api/v1/auth/login", strings.NewReader("{bad"))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	id := rec.Header().Get("X-Request-ID")
	if rec.Code != 400 || id == "" || !strings.Contains(rec.Body.String(), id) {
		t.Fatalf("code=%d id=%q body=%s", rec.Code, id, rec.Body)
	}
}

func TestGatewayRefreshesJWKSOverGRPCOnKeyRotation(t *testing.T) {
	_, priv2, _ := ed25519.GenerateKey(nil)
	rotatedSigner, _ := jwtkeys.NewSigner(priv2, "rotated-kid", "iss", "aud", time.Minute)
	jwk := rotatedSigner.PublicJWK()

	mockClient := &mockAuthClient{
		getJWKSFunc: func(context.Context, *authv1.GetJWKSRequest, ...grpc.CallOption) (*authv1.GetJWKSResponse, error) {
			return &authv1.GetJWKSResponse{
				Keys: []*authv1.JWK{{
					Kty: jwk.Kty, Crv: jwk.Crv, Kid: jwk.Kid, Alg: jwk.Alg, Use: jwk.Use, X: jwk.X,
				}},
			}, nil
		},
	}

	verifier, err := jwtkeys.NewVerifier(nil, "iss", "aud", jwtkeys.WithKeySetProvider(NewGRPCJWKSProvider(mockClient), time.Second))
	if err != nil {
		t.Fatal(err)
	}
	srv := NewServerHandler(NewHandler(mockClient), Options{
		Log:            slog.New(slog.NewTextHandler(io.Discard, nil)),
		Verifier:       verifier,
		GeneralLimiter: allow,
		AuthLimiter:    allow,
	})

	tok, _, _ := rotatedSigner.Sign(uuid.New(), uuid.New(), time.Now())
	rec := do(srv, "GET", "/api/v1/me", "Bearer "+tok)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"kind":"session"`) {
		t.Fatalf("expected 200 with session principal after JWKS fetch, got %d %s", rec.Code, rec.Body)
	}
}

func TestGatewayAuthenticatesAPITokenBearer(t *testing.T) {
	patSecret := "kr0n_pat_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	mockClient := &mockAuthClient{
		validateAPITokenFunc: func(_ context.Context, in *authv1.ValidateAPITokenRequest, _ ...grpc.CallOption) (*authv1.ValidateAPITokenResponse, error) {
			if in.GetToken() == patSecret {
				return &authv1.ValidateAPITokenResponse{
					TokenId:     "tok-1",
					OrgId:       "org-1",
					UserId:      "user-1",
					Permissions: []string{"org:read"},
				}, nil
			}
			return nil, errors.New("invalid pat")
		},
		getOrganizationFunc: func(_ context.Context, in *authv1.GetOrganizationRequest, _ ...grpc.CallOption) (*authv1.GetOrganizationResponse, error) {
			if in.GetCaller().GetKind() != "api_token" || in.GetCaller().GetTokenOrgId() != "org-1" {
				t.Fatalf("unexpected caller principal: %+v", in.GetCaller())
			}
			return &authv1.GetOrganizationResponse{Id: in.GetOrgId(), Name: "Acme", Slug: "acme"}, nil
		},
	}

	srv := NewServerHandler(NewHandler(mockClient), Options{
		Log:            slog.New(slog.NewTextHandler(io.Discard, nil)),
		GeneralLimiter: allow,
		AuthLimiter:    allow,
	})

	if rec := do(srv, "GET", "/api/v1/orgs/org-1", "Bearer kr0n_pat_bad"); rec.Code != 401 {
		t.Fatalf("expected 401 for invalid PAT, got %d", rec.Code)
	}

	rec := do(srv, "GET", "/api/v1/orgs/org-1", "Bearer "+patSecret)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"slug":"acme"`) {
		t.Fatalf("expected 200 for valid PAT, got %d %s", rec.Code, rec.Body.String())
	}
}

func TestGatewayAPITokenRejectedOnPersonalAccountEndpoints(t *testing.T) {
	patSecret := "kr0n_pat_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	personalCalls := 0
	mockClient := &mockAuthClient{
		validateAPITokenFunc: func(context.Context, *authv1.ValidateAPITokenRequest, ...grpc.CallOption) (*authv1.ValidateAPITokenResponse, error) {
			return &authv1.ValidateAPITokenResponse{TokenId: "tok-1", OrgId: "org-1", UserId: "user-1", Permissions: []string{"org:read"}}, nil
		},
		changePasswordFunc: func(context.Context, *authv1.ChangePasswordRequest, ...grpc.CallOption) (*authv1.ChangePasswordResponse, error) {
			personalCalls++
			return &authv1.ChangePasswordResponse{}, nil
		},
		listSessionsFunc: func(context.Context, *authv1.ListSessionsRequest, ...grpc.CallOption) (*authv1.ListSessionsResponse, error) {
			personalCalls++
			return &authv1.ListSessionsResponse{}, nil
		},
		revokeSessionFunc: func(context.Context, *authv1.RevokeSessionRequest, ...grpc.CallOption) (*authv1.RevokeSessionResponse, error) {
			personalCalls++
			return &authv1.RevokeSessionResponse{}, nil
		},
	}
	srv := NewServerHandler(NewHandler(mockClient), Options{
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)), GeneralLimiter: allow, AuthLimiter: allow,
	})

	for _, tc := range []struct{ method, path string }{
		{"POST", "/api/v1/auth/password/change"},
		{"GET", "/api/v1/auth/sessions"},
		{"DELETE", "/api/v1/auth/sessions/11111111-1111-1111-1111-111111111111"},
		{"GET", "/api/v1/me"},
	} {
		if rec := do(srv, tc.method, tc.path, "Bearer "+patSecret); rec.Code != 403 {
			t.Fatalf("%s %s with API token: expected 403, got %d %s", tc.method, tc.path, rec.Code, rec.Body)
		}
	}
	if personalCalls != 0 {
		t.Fatalf("personal-account RPCs must never be reached by an API token, got %d calls", personalCalls)
	}
}

func TestGatewayOrgAuditEndpointGatedByAuditReadPermission(t *testing.T) {
	patSecret := "kr0n_pat_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	allowed := false
	mockClient := &mockAuthClient{
		validateAPITokenFunc: func(_ context.Context, in *authv1.ValidateAPITokenRequest, _ ...grpc.CallOption) (*authv1.ValidateAPITokenResponse, error) {
			if in.GetToken() == patSecret {
				return &authv1.ValidateAPITokenResponse{
					TokenId:     "tok-1",
					OrgId:       "org-1",
					UserId:      "user-1",
					Permissions: []string{"audit:read"},
				}, nil
			}
			return nil, errors.New("invalid pat")
		},
		listAuditEventsFunc: func(_ context.Context, in *authv1.ListAuditEventsRequest, _ ...grpc.CallOption) (*authv1.ListAuditEventsResponse, error) {
			if !allowed {
				return nil, status.Error(codes.PermissionDenied, "permission denied")
			}
			return &authv1.ListAuditEventsResponse{
				Events: []*authv1.AuditEventInfo{{
					Id:           "ev-1",
					OrgId:        in.GetOrgId(),
					ActorUserId:  "user-1",
					ActorType:    "user",
					Action:       "apitoken.created",
					ResourceType: "api_token",
					ResourceId:   "tok-1",
					MetadataJson: `{"name":"ci"}`,
				}},
			}, nil
		},
	}

	srv := NewServerHandler(NewHandler(mockClient), Options{
		Log:            slog.New(slog.NewTextHandler(io.Discard, nil)),
		GeneralLimiter: allow,
		AuthLimiter:    allow,
	})

	// 1. Denied when caller lacks audit:read
	if rec := do(srv, "GET", "/api/v1/orgs/org-1/audit?limit=10", "Bearer "+patSecret); rec.Code != 403 {
		t.Fatalf("expected 403 when lacking audit:read, got %d %s", rec.Code, rec.Body.String())
	}

	// 2. Allowed when caller holds audit:read
	allowed = true
	rec := do(srv, "GET", "/api/v1/orgs/org-1/audit?limit=10", "Bearer "+patSecret)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"apitoken.created"`) {
		t.Fatalf("expected 200 with audit events, got %d %s", rec.Code, rec.Body.String())
	}
}
