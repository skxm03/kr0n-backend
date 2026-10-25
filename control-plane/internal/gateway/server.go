package gateway

import (
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"time"

	authv1 "github.com/skxm03/kr0n-backend/control-plane/gen/auth/v1"
	"github.com/skxm03/kr0n-backend/control-plane/internal/auth/jwtkeys"
	"github.com/skxm03/kr0n-backend/control-plane/internal/gateway/middleware"
	"github.com/skxm03/kr0n-backend/control-plane/internal/ratelimit"
)

// NewGRPCJWKSProvider adapts an AuthServiceClient into a jwtkeys.KeySetProvider.
func NewGRPCJWKSProvider(c AuthServiceClient) jwtkeys.KeySetProvider {
	return grpcJWKSProvider{client: c}
}

type grpcJWKSProvider struct {
	client AuthServiceClient
}

func (p grpcJWKSProvider) FetchJWKS(ctx context.Context) ([]jwtkeys.JWK, error) {
	resp, err := p.client.GetJWKS(ctx, &authv1.GetJWKSRequest{})
	if err != nil {
		return nil, err
	}
	out := make([]jwtkeys.JWK, 0, len(resp.GetKeys()))
	for _, k := range resp.GetKeys() {
		out = append(out, jwtkeys.JWK{
			Kty: k.GetKty(),
			Crv: k.GetCrv(),
			Kid: k.GetKid(),
			Alg: k.GetAlg(),
			Use: k.GetUse(),
			X:   k.GetX(),
		})
	}
	return out, nil
}

// NewGRPCAPITokenVerifier adapts an AuthServiceClient into a middleware.APITokenVerifier.
func NewGRPCAPITokenVerifier(c AuthServiceClient) middleware.APITokenVerifier {
	return grpcAPITokenVerifier{client: c}
}

type grpcAPITokenVerifier struct {
	client AuthServiceClient
}

func (v grpcAPITokenVerifier) VerifyAPIToken(ctx context.Context, rawToken string) (*middleware.Principal, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	resp, err := v.client.ValidateAPIToken(ctx, &authv1.ValidateAPITokenRequest{Token: rawToken})
	if err != nil {
		return nil, err
	}
	return &middleware.Principal{
		UserID:      resp.GetUserId(),
		Kind:        middleware.PrincipalKindAPIToken,
		OrgID:       resp.GetOrgId(),
		TokenID:     resp.GetTokenId(),
		Permissions: resp.GetPermissions(),
	}, nil
}

// Options configures the production middleware chain built by NewServerHandler.
type Options struct {
	Env              string
	Log              *slog.Logger
	Verifier         middleware.TokenVerifier
	APITokenVerifier middleware.APITokenVerifier
	GeneralLimiter   ratelimit.Limiter // per-IP for all traffic, per-user for authenticated routes
	AuthLimiter      ratelimit.Limiter // stricter, per-IP, for credential endpoints
	TrustedProxies   []*net.IPNet
	Ready            func(ctx context.Context) error
	MaxBodyBytes     int64
}

// NewServerHandler wires routes plus the full middleware chain:
// request-id → recover → access log → security headers → body cap → general rate limit → route.
// Credential endpoints add a stricter limiter that fails closed; protected routes require a JWT or PAT.
func NewServerHandler(h *Handler, o Options) http.Handler {
	if o.MaxBodyBytes == 0 {
		o.MaxBodyBytes = 1 << 20
	}
	if h != nil {
		if o.Env != "" {
			h.env = o.Env
		}
		if len(o.TrustedProxies) > 0 {
			h.trustedProxies = o.TrustedProxies
		}
	}
	if o.APITokenVerifier == nil && h != nil && h.authClient != nil {
		o.APITokenVerifier = NewGRPCAPITokenVerifier(h.authClient)
	}
	ip := func(r *http.Request) string { return "ip:" + middleware.ClientIP(r, o.TrustedProxies) }
	user := func(r *http.Request) string {
		if p, ok := middleware.PrincipalFromContext(r.Context()); ok {
			return "user:" + p.UserID
		}
		return ip(r)
	}

	authLimit := middleware.RateLimit(o.AuthLimiter, ip, false, o.Log)
	protect := func(next http.HandlerFunc) http.Handler {
		return middleware.Chain(next,
			middleware.Authenticate(o.Verifier, o.APITokenVerifier),
			middleware.RateLimit(o.GeneralLimiter, user, true, o.Log))
	}
	// protectUser is for personal-account routes: sessions only, API tokens are rejected.
	protectUser := func(next http.HandlerFunc) http.Handler {
		return middleware.Chain(next,
			middleware.Authenticate(o.Verifier, o.APITokenVerifier),
			middleware.RejectAPIToken(),
			middleware.RateLimit(o.GeneralLimiter, user, true, o.Log))
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		if o.Ready != nil && o.Ready(ctx) != nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "unavailable"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
	})

	mux.Handle("POST /api/v1/auth/register", authLimit(http.HandlerFunc(h.Register)))
	mux.Handle("POST /api/v1/auth/login", authLimit(http.HandlerFunc(h.Login)))
	mux.Handle("POST /api/v1/auth/refresh", authLimit(http.HandlerFunc(h.Refresh)))
	mux.Handle("POST /api/v1/auth/logout", authLimit(http.HandlerFunc(h.Logout)))
	mux.Handle("POST /api/v1/auth/verify-email", authLimit(http.HandlerFunc(h.VerifyEmail)))
	mux.Handle("POST /api/v1/auth/resend-verification", authLimit(http.HandlerFunc(h.ResendVerification)))
	mux.Handle("POST /api/v1/auth/password-reset/request", authLimit(http.HandlerFunc(h.RequestPasswordReset)))
	mux.Handle("POST /api/v1/auth/password-reset/confirm", authLimit(http.HandlerFunc(h.ConfirmPasswordReset)))
	mux.Handle("GET /api/v1/auth/github/start", authLimit(http.HandlerFunc(h.GitHubOAuthStart)))
	mux.Handle("GET /api/v1/auth/github/callback", authLimit(http.HandlerFunc(h.GitHubOAuthCallback)))

	mux.Handle("POST /api/v1/auth/password/change", protectUser(h.ChangePassword))
	mux.Handle("GET /api/v1/me", protectUser(h.GetMe))
	mux.Handle("GET /api/v1/auth/sessions", protectUser(h.ListSessions))
	mux.Handle("DELETE /api/v1/auth/sessions/{id}", protectUser(h.RevokeSession))

	mux.Handle("GET /api/v1/roles", protect(h.ListRoles))
	mux.Handle("POST /api/v1/orgs", protect(h.CreateOrg))
	mux.Handle("GET /api/v1/orgs", protect(h.ListOrgs))
	mux.Handle("GET /api/v1/orgs/{id}", protect(h.GetOrg))
	mux.Handle("PATCH /api/v1/orgs/{id}", protect(h.UpdateOrg))
	mux.Handle("DELETE /api/v1/orgs/{id}", protect(h.DeleteOrg))
	mux.Handle("GET /api/v1/orgs/{id}/members", protect(h.ListMembers))
	mux.Handle("POST /api/v1/orgs/{id}/members", protect(h.AddMember))
	mux.Handle("PATCH /api/v1/orgs/{id}/members/{user_id}", protect(h.UpdateMemberRole))
	mux.Handle("DELETE /api/v1/orgs/{id}/members/{user_id}", protect(h.RemoveMember))
	mux.Handle("POST /api/v1/orgs/{id}/invites", protect(h.CreateInvite))
	mux.Handle("POST /api/v1/orgs/invites/accept", protect(h.AcceptInvite))
	mux.Handle("DELETE /api/v1/orgs/{id}/invites/{invite_id}", protect(h.RevokeInvite))
	mux.Handle("POST /api/v1/orgs/{id}/tokens", protect(h.CreateAPIToken))
	mux.Handle("GET /api/v1/orgs/{id}/tokens", protect(h.ListAPITokens))
	mux.Handle("DELETE /api/v1/orgs/{id}/tokens/{token_id}", protect(h.RevokeAPIToken))
	mux.Handle("GET /api/v1/orgs/{id}/audit", protect(h.ListAuditEvents))

	return middleware.Chain(mux,
		middleware.RequestID(),
		middleware.WithClientIP(o.TrustedProxies),
		middleware.Recover(o.Log),
		middleware.AccessLog(o.Log),
		middleware.SecureHeaders(),
		middleware.MaxBody(o.MaxBodyBytes),
		middleware.RateLimit(o.GeneralLimiter, ip, true, o.Log),
	)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
