package middleware

import (
	"context"
	"crypto/subtle"
	"net/http"
	"strings"
	"time"

	"github.com/skxm03/kr0n-backend/control-plane/internal/auth/jwtkeys"
)

const (
	// PrincipalKindSession identifies a user authenticated via an EdDSA JWT access token.
	PrincipalKindSession = "session"
	// PrincipalKindAPIToken identifies a caller authenticated via an opaque API token (P6).
	PrincipalKindAPIToken = "api_token"
)

// Principal is the authenticated caller attached to the request context.
type Principal struct {
	UserID      string
	SessionID   string
	Kind        string
	OrgID       string
	TokenID     string
	Permissions []string
}

const (
	principalKey ctxKey = iota + 100
	principalTrackerKey
)

type principalTracker struct {
	p *Principal
}

// WithPrincipalTracker attaches a mutable holder to ctx so outer middlewares (such as audit_log)
// that run before Authenticate can still inspect the resolved Principal after downstream handlers return.
func WithPrincipalTracker(ctx context.Context) context.Context {
	if _, ok := ctx.Value(principalTrackerKey).(*principalTracker); ok {
		return ctx
	}
	return context.WithValue(ctx, principalTrackerKey, &principalTracker{})
}

// WithPrincipal attaches an authenticated Principal to ctx (and updates any outer principalTracker).
func WithPrincipal(ctx context.Context, p *Principal) context.Context {
	if tracker, ok := ctx.Value(principalTrackerKey).(*principalTracker); ok && tracker != nil {
		tracker.p = p
	}
	return context.WithValue(ctx, principalKey, p)
}

// PrincipalFromContext returns the authenticated principal, if any.
func PrincipalFromContext(ctx context.Context) (*Principal, bool) {
	if p, ok := ctx.Value(principalKey).(*Principal); ok && p != nil {
		return p, true
	}
	if tracker, ok := ctx.Value(principalTrackerKey).(*principalTracker); ok && tracker != nil && tracker.p != nil {
		return tracker.p, true
	}
	return nil, false
}

// TokenVerifier validates an access token.
type TokenVerifier interface {
	VerifyContext(ctx context.Context, token string, now time.Time) (*jwtkeys.Claims, error)
}

// APITokenVerifier validates an opaque `kr0n_pat_...` API token.
type APITokenVerifier interface {
	VerifyAPIToken(ctx context.Context, rawToken string) (*Principal, error)
}

// Authenticate requires a valid "Authorization: Bearer <jwt|kr0n_pat_...>" header. Every failure
// returns the same 401 body so callers cannot distinguish expired, malformed, or forged tokens.
//
// Architectural note on stateless JWT revocation window: Session principals are authenticated
// locally via Ed25519 JWT verification (default 15m TTL) without a synchronous DB round-trip per
// request, trading a bounded post-revocation window (up to access-token TTL) for horizontal
// gateway scalability. Immediate revocation is enforced on refresh-token rotation and on all
// sensitive credential mutations (password change, password reset, OAuth link).
func Authenticate(v TokenVerifier, patVerifiers ...APITokenVerifier) Middleware {
	var pat APITokenVerifier
	if len(patVerifiers) > 0 && patVerifiers[0] != nil {
		pat = patVerifiers[0]
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodOptions {
				next.ServeHTTP(w, r)
				return
			}
			rawHeader := r.Header.Get("Authorization")
			var rawToken string
			if rawHeader != "" {
				scheme, token, ok := strings.Cut(rawHeader, " ")
				if !ok || subtle.ConstantTimeCompare([]byte(strings.ToLower(scheme)), []byte("bearer")) != 1 || token == "" {
					unauthorized(w, r)
					return
				}
				rawToken = strings.TrimSpace(token)
			} else {
				// Cookie-based authentication: extract access_token from HttpOnly cookie
				if c, err := r.Cookie("access_token"); err == nil && strings.TrimSpace(c.Value) != "" {
					rawToken = strings.TrimSpace(c.Value)
				}
			}

			if rawToken == "" {
				if v == nil {
					if _, ok := PrincipalFromContext(r.Context()); ok {
						next.ServeHTTP(w, r)
						return
					}
				}
				unauthorized(w, r)
				return
			}
			if strings.HasPrefix(rawToken, "kr0n_pat_") {
				if pat == nil {
					unauthorized(w, r)
					return
				}
				p, err := pat.VerifyAPIToken(r.Context(), rawToken)
				if err != nil || p == nil || p.UserID == "" {
					unauthorized(w, r)
					return
				}
				if p.Kind == "" {
					p.Kind = PrincipalKindAPIToken
				}
				next.ServeHTTP(w, r.WithContext(WithPrincipal(r.Context(), p)))
				return
			}

			if v == nil {
				unauthorized(w, r)
				return
			}
			claims, err := v.VerifyContext(r.Context(), rawToken, time.Now())
			if err != nil {
				unauthorized(w, r)
				return
			}
			p := &Principal{
				UserID:    claims.Subject,
				SessionID: claims.SessionID,
				Kind:      PrincipalKindSession,
			}
			next.ServeHTTP(w, r.WithContext(WithPrincipal(r.Context(), p)))
		})
	}
}

// RejectAPIToken denies API-token principals on user-account routes (password change, personal
// sessions, profile). API tokens are organization-scoped machine credentials; they act on behalf
// of an org, never on the creating user's personal account. Must run after Authenticate.
func RejectAPIToken() Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if p, ok := PrincipalFromContext(r.Context()); ok && p != nil && p.Kind == PrincipalKindAPIToken {
				WriteError(w, r, http.StatusForbidden, "api tokens cannot access personal account endpoints", "FORBIDDEN")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// RequirePermission ensures the authenticated principal holds all specified permissions.
func RequirePermission(permissions ...string) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p, ok := PrincipalFromContext(r.Context())
			if !ok || p == nil {
				unauthorized(w, r)
				return
			}
			if len(permissions) == 0 {
				next.ServeHTTP(w, r)
				return
			}
			held := make(map[string]bool)
			for _, perm := range p.Permissions {
				held[perm] = true
			}
			for _, required := range permissions {
				if !held[required] {
					WriteError(w, r, http.StatusForbidden, "insufficient permissions", "FORBIDDEN")
					return
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

func unauthorized(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("WWW-Authenticate", `Bearer realm="kr0n"`)
	WriteError(w, r, http.StatusUnauthorized, "authentication required", "UNAUTHORIZED")
}
