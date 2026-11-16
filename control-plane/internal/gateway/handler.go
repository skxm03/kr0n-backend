package gateway

import (
	"context"
	"crypto/subtle"
	"net"
	"net/http"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	authv1 "github.com/skxm03/kr0n-backend/control-plane/gen/auth/v1"
	"github.com/skxm03/kr0n-backend/control-plane/internal/gateway/middleware"
)

// AuthServiceClient is an alias for the full generated gRPC client contract.
type AuthServiceClient = authv1.AuthServiceClient

// OAuthClient defines the gRPC client contract required by the OAuth handlers.
type OAuthClient interface {
	StartGitHubOAuth(ctx context.Context, in *authv1.StartGitHubOAuthRequest, opts ...grpc.CallOption) (*authv1.StartGitHubOAuthResponse, error)
	CompleteGitHubOAuth(ctx context.Context, in *authv1.CompleteGitHubOAuthRequest, opts ...grpc.CallOption) (*authv1.CompleteGitHubOAuthResponse, error)
}

const githubOAuthCookieName = "kr0n_gh_oauth"

// Handler handles HTTP requests for custom non-gRPC endpoints (e.g. GitHub OAuth).
type Handler struct {
	authClient     AuthServiceClient
	env            string
	trustedProxies []*net.IPNet
}

// NewHandler creates a new API Gateway Handler.
func NewHandler(authClient AuthServiceClient) *Handler {
	return &Handler{
		authClient: authClient,
		env:        "development",
	}
}

// GitHubOAuthStart handles GET /api/v1/auth/github/start by setting an HttpOnly state+PKCE cookie
// and redirecting to GitHub's authorize endpoint.
func (h *Handler) GitHubOAuthStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.writeError(w, http.StatusMethodNotAllowed, "method not allowed", "METHOD_NOT_ALLOWED")
		return
	}

	ctx, cancel := h.grpcContext(r, 5*time.Second)
	defer cancel()

	grpcResp, err := h.authClient.StartGitHubOAuth(ctx, &authv1.StartGitHubOAuthRequest{})
	if err != nil {
		h.writeGRPCError(w, err)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     githubOAuthCookieName,
		Value:    grpcResp.GetState() + "." + grpcResp.GetCodeVerifier(),
		Path:     "/api/v1/auth/github/callback",
		MaxAge:   600,
		HttpOnly: true,
		Secure:   h.isSecureRequest(r),
		SameSite: http.SameSiteLaxMode,
	})

	http.Redirect(w, r, grpcResp.GetAuthorizeUrl(), http.StatusFound)
}

// GitHubOAuthCallback handles GET /api/v1/auth/github/callback by verifying the CSRF state cookie,
// exchanging the code + PKCE verifier via the Auth gRPC service, and returning a session token pair.
func (h *Handler) GitHubOAuthCallback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.writeError(w, http.StatusMethodNotAllowed, "method not allowed", "METHOD_NOT_ALLOWED")
		return
	}

	// Clear the state+PKCE cookie immediately (single-use) with matching attributes.
	http.SetCookie(w, &http.Cookie{
		Name:     githubOAuthCookieName,
		Value:    "",
		Path:     "/api/v1/auth/github/callback",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   h.isSecureRequest(r),
		SameSite: http.SameSiteLaxMode,
	})

	code := strings.TrimSpace(r.URL.Query().Get("code"))
	state := strings.TrimSpace(r.URL.Query().Get("state"))
	cookie, err := r.Cookie(githubOAuthCookieName)
	if err != nil || code == "" || state == "" {
		h.writeError(w, http.StatusBadRequest, "invalid or missing oauth state or code", "INVALID_OAUTH_STATE")
		return
	}

	cookieState, codeVerifier, ok := strings.Cut(cookie.Value, ".")
	if !ok || cookieState == "" || codeVerifier == "" ||
		subtle.ConstantTimeCompare([]byte(state), []byte(cookieState)) != 1 {
		h.writeError(w, http.StatusBadRequest, "invalid oauth state", "INVALID_OAUTH_STATE")
		return
	}

	ctx, cancel := h.grpcContext(r, 10*time.Second)
	defer cancel()

	grpcResp, err := h.authClient.CompleteGitHubOAuth(ctx, &authv1.CompleteGitHubOAuthRequest{
		Code:         code,
		CodeVerifier: codeVerifier,
		UserAgent:    r.UserAgent(),
		ClientIp:     ExtractClientIP(r),
	})
	if err != nil {
		h.writeGRPCError(w, err)
		return
	}

	WriteJSON(w, http.StatusOK, LoginResponseDTO{
		AccessToken:  grpcResp.GetAccessToken(),
		RefreshToken: grpcResp.GetRefreshToken(),
		TokenType:    grpcResp.GetTokenType(),
		ExpiresIn:    grpcResp.GetExpiresIn(),
		User: UserDTO{
			ID:          grpcResp.GetUser().GetId(),
			Email:       grpcResp.GetUser().GetEmail(),
			DisplayName: grpcResp.GetUser().GetDisplayName(),
			Status:      grpcResp.GetUser().GetStatus(),
		},
	})
}

func (h *Handler) grpcContext(r *http.Request, timeout time.Duration) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithTimeout(r.Context(), timeout)
	pairs := make([]string, 0, 6)
	if reqID := middleware.RequestIDFromContext(r.Context()); reqID != "" {
		pairs = append(pairs, "x-request-id", reqID)
	}
	if ip := ExtractClientIP(r); ip != "" {
		pairs = append(pairs, "x-client-ip", ip)
	}
	if ua := r.UserAgent(); ua != "" {
		pairs = append(pairs, "x-user-agent", ua)
	}
	if len(pairs) > 0 {
		ctx = metadata.AppendToOutgoingContext(ctx, pairs...)
	}
	return ctx, cancel
}

func (h *Handler) isSecureRequest(r *http.Request) bool {
	if r.TLS != nil || !isDevEnv(h.env) {
		return true
	}
	if middleware.IsTrustedProxy(r, h.trustedProxies) && strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https") {
		return true
	}
	return false
}

func isDevEnv(env string) bool {
	return strings.EqualFold(env, "dev") || strings.EqualFold(env, "development")
}

func (h *Handler) writeGRPCError(w http.ResponseWriter, err error) {
	statusCode, message, code := TranslateGRPCStatus(err)
	h.writeError(w, statusCode, message, code)
}

func (h *Handler) writeError(w http.ResponseWriter, statusCode int, message, code string) {
	WriteErrorJSON(nil, w, statusCode, message, code)
}
