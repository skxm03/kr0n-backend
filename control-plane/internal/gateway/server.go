package gateway

import (
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"

	authv1 "github.com/skxm03/kr0n-backend/control-plane/gen/auth/v1"
	"github.com/skxm03/kr0n-backend/control-plane/internal/auth/jwtkeys"
	"github.com/skxm03/kr0n-backend/control-plane/internal/gateway/middleware"
	"github.com/skxm03/kr0n-backend/control-plane/internal/gateway/ratelimit"
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

// Options configures the gateway router and middleware stack.
type Options struct {
	Env              string
	Log              *slog.Logger
	Verifier         middleware.TokenVerifier
	APITokenVerifier middleware.APITokenVerifier
	GeneralLimiter   ratelimit.Limiter
	AuthLimiter      ratelimit.Limiter
	TrustedProxies   []*net.IPNet
	Ready            func(ctx context.Context) error
	MaxBodyBytes     int64
}

// NewServerHandler builds the chi router and middleware stack for the API Gateway.
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

	ipKey := func(r *http.Request) string { return "ip:" + middleware.ClientIP(r, o.TrustedProxies) }
	userKey := func(r *http.Request) string {
		if p, ok := middleware.PrincipalFromContext(r.Context()); ok {
			return "user:" + p.UserID
		}
		return ipKey(r)
	}

	r := chi.NewRouter()
	r.Use(
		middleware.RequestID,
		middleware.WithClientIP(o.TrustedProxies),
		middleware.Recover(o.Log),
		middleware.AccessLog(o.Log),
		chimw.SetHeader("X-Content-Type-Options", "nosniff"),
		chimw.SetHeader("X-Frame-Options", "DENY"),
		chimw.SetHeader("Referrer-Policy", "no-referrer"),
		chimw.SetHeader("Cache-Control", "no-store"),
		chimw.SetHeader("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'"),
		chimw.SetHeader("Strict-Transport-Security", "max-age=63072000; includeSubDomains"),
		chimw.RequestSize(o.MaxBodyBytes),
		middleware.RateLimit(o.GeneralLimiter, ipKey, true, o.Log),
	)

	r.Get("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	r.Get("/readyz", func(w http.ResponseWriter, req *http.Request) {
		ctx, cancel := context.WithTimeout(req.Context(), 2*time.Second)
		defer cancel()
		if o.Ready != nil && o.Ready(ctx) != nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "unavailable"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
	})

	// Initialize grpc-gateway ServeMux with snake_case JSON, metadata propagation, and error envelope
	gwMux := NewGatewayServeMux(o.TrustedProxies)
	if h != nil && h.authClient != nil {
		if err := authv1.RegisterAuthServiceHandlerClient(context.Background(), gwMux, h.authClient); err != nil {
			if o.Log != nil {
				o.Log.Error("failed to register auth grpc-gateway", "err", err)
			}
		}
	}

	// Public credential & OAuth routes (stricter per-IP limiter, fails closed on Redis outage)
	r.Group(func(r chi.Router) {
		r.Use(
			middleware.RateLimit(o.AuthLimiter, ipKey, false, o.Log),
			EnforceJSONContentType,
		)
		r.Get("/api/v1/auth/github/start", h.GitHubOAuthStart)
		r.Get("/api/v1/auth/github/callback", h.GitHubOAuthCallback)
		r.Post("/api/v1/auth/register", gwMux.ServeHTTP)
		r.Post("/api/v1/auth/login", gwMux.ServeHTTP)
		r.Post("/api/v1/auth/refresh", gwMux.ServeHTTP)
		r.Post("/api/v1/auth/logout", gwMux.ServeHTTP)
		r.Post("/api/v1/auth/verify-email", gwMux.ServeHTTP)
		r.Post("/api/v1/auth/resend-verification", gwMux.ServeHTTP)
		r.Post("/api/v1/auth/password-reset/request", gwMux.ServeHTTP)
		r.Post("/api/v1/auth/password-reset/confirm", gwMux.ServeHTTP)
	})

	// Personal-account routes (session JWT only; API tokens are rejected)
	r.Group(func(r chi.Router) {
		r.Use(
			middleware.Authenticate(o.Verifier, o.APITokenVerifier),
			middleware.RejectAPIToken(),
			middleware.RateLimit(o.GeneralLimiter, userKey, true, o.Log),
			EnforceJSONContentType,
		)
		r.Post("/api/v1/auth/password/change", gwMux.ServeHTTP)
		r.Get("/api/v1/me", gwMux.ServeHTTP)
		r.Get("/api/v1/auth/sessions", gwMux.ServeHTTP)
		r.Delete("/api/v1/auth/sessions/{id}", gwMux.ServeHTTP)
	})

	// Organization & RBAC routes (session JWT or org-scoped API token)
	r.Group(func(r chi.Router) {
		r.Use(
			middleware.Authenticate(o.Verifier, o.APITokenVerifier),
			middleware.RateLimit(o.GeneralLimiter, userKey, true, o.Log),
			EnforceJSONContentType,
		)
		r.Get("/api/v1/roles", gwMux.ServeHTTP)
		r.Post("/api/v1/orgs", gwMux.ServeHTTP)
		r.Get("/api/v1/orgs", gwMux.ServeHTTP)
		r.HandleFunc("/api/v1/orgs/*", gwMux.ServeHTTP)
	})

	return r
}

// EnforceJSONContentType ensures request Content-Type is application/json for POST, PUT, and PATCH methods.
func EnforceJSONContentType(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodPatch {
			ct := r.Header.Get("Content-Type")
			if !strings.HasPrefix(strings.ToLower(ct), "application/json") {
				writeErrorJSON(r.Context(), w, http.StatusUnsupportedMediaType, "content-type must be application/json", "UNSUPPORTED_MEDIA_TYPE")
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
