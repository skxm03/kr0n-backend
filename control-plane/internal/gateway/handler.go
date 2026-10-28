package gateway

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	authv1 "github.com/skxm03/kr0n-backend/control-plane/gen/auth/v1"
	"github.com/skxm03/kr0n-backend/control-plane/internal/gateway/middleware"
)

// AuthServiceClient defines the gRPC client contract required by the Gateway handler.
type AuthServiceClient interface {
	Register(ctx context.Context, in *authv1.RegisterRequest, opts ...grpc.CallOption) (*authv1.RegisterResponse, error)
	Login(ctx context.Context, in *authv1.LoginRequest, opts ...grpc.CallOption) (*authv1.LoginResponse, error)
	Refresh(ctx context.Context, in *authv1.RefreshRequest, opts ...grpc.CallOption) (*authv1.RefreshResponse, error)
	Logout(ctx context.Context, in *authv1.LogoutRequest, opts ...grpc.CallOption) (*authv1.LogoutResponse, error)
	VerifyEmail(ctx context.Context, in *authv1.VerifyEmailRequest, opts ...grpc.CallOption) (*authv1.VerifyEmailResponse, error)
	GetJWKS(ctx context.Context, in *authv1.GetJWKSRequest, opts ...grpc.CallOption) (*authv1.GetJWKSResponse, error)
	ResendVerification(ctx context.Context, in *authv1.ResendVerificationRequest, opts ...grpc.CallOption) (*authv1.ResendVerificationResponse, error)
	RequestPasswordReset(ctx context.Context, in *authv1.RequestPasswordResetRequest, opts ...grpc.CallOption) (*authv1.RequestPasswordResetResponse, error)
	ConfirmPasswordReset(ctx context.Context, in *authv1.ConfirmPasswordResetRequest, opts ...grpc.CallOption) (*authv1.ConfirmPasswordResetResponse, error)
	ChangePassword(ctx context.Context, in *authv1.ChangePasswordRequest, opts ...grpc.CallOption) (*authv1.ChangePasswordResponse, error)
	GetMe(ctx context.Context, in *authv1.GetMeRequest, opts ...grpc.CallOption) (*authv1.GetMeResponse, error)
	ListSessions(ctx context.Context, in *authv1.ListSessionsRequest, opts ...grpc.CallOption) (*authv1.ListSessionsResponse, error)
	RevokeSession(ctx context.Context, in *authv1.RevokeSessionRequest, opts ...grpc.CallOption) (*authv1.RevokeSessionResponse, error)
	StartGitHubOAuth(ctx context.Context, in *authv1.StartGitHubOAuthRequest, opts ...grpc.CallOption) (*authv1.StartGitHubOAuthResponse, error)
	CompleteGitHubOAuth(ctx context.Context, in *authv1.CompleteGitHubOAuthRequest, opts ...grpc.CallOption) (*authv1.CompleteGitHubOAuthResponse, error)
	CheckPermission(ctx context.Context, in *authv1.CheckPermissionRequest, opts ...grpc.CallOption) (*authv1.CheckPermissionResponse, error)
	ListRoles(ctx context.Context, in *authv1.ListRolesRequest, opts ...grpc.CallOption) (*authv1.ListRolesResponse, error)
	CreateOrganization(ctx context.Context, in *authv1.CreateOrganizationRequest, opts ...grpc.CallOption) (*authv1.CreateOrganizationResponse, error)
	ListOrganizations(ctx context.Context, in *authv1.ListOrganizationsRequest, opts ...grpc.CallOption) (*authv1.ListOrganizationsResponse, error)
	GetOrganization(ctx context.Context, in *authv1.GetOrganizationRequest, opts ...grpc.CallOption) (*authv1.GetOrganizationResponse, error)
	UpdateOrganization(ctx context.Context, in *authv1.UpdateOrganizationRequest, opts ...grpc.CallOption) (*authv1.UpdateOrganizationResponse, error)
	DeleteOrganization(ctx context.Context, in *authv1.DeleteOrganizationRequest, opts ...grpc.CallOption) (*authv1.DeleteOrganizationResponse, error)
	ListMembers(ctx context.Context, in *authv1.ListMembersRequest, opts ...grpc.CallOption) (*authv1.ListMembersResponse, error)
	AddMember(ctx context.Context, in *authv1.AddMemberRequest, opts ...grpc.CallOption) (*authv1.AddMemberResponse, error)
	UpdateMemberRole(ctx context.Context, in *authv1.UpdateMemberRoleRequest, opts ...grpc.CallOption) (*authv1.UpdateMemberRoleResponse, error)
	RemoveMember(ctx context.Context, in *authv1.RemoveMemberRequest, opts ...grpc.CallOption) (*authv1.RemoveMemberResponse, error)
	CreateInvite(ctx context.Context, in *authv1.CreateInviteRequest, opts ...grpc.CallOption) (*authv1.CreateInviteResponse, error)
	AcceptInvite(ctx context.Context, in *authv1.AcceptInviteRequest, opts ...grpc.CallOption) (*authv1.AcceptInviteResponse, error)
	RevokeInvite(ctx context.Context, in *authv1.RevokeInviteRequest, opts ...grpc.CallOption) (*authv1.RevokeInviteResponse, error)
	CreateAPIToken(ctx context.Context, in *authv1.CreateAPITokenRequest, opts ...grpc.CallOption) (*authv1.CreateAPITokenResponse, error)
	ListAPITokens(ctx context.Context, in *authv1.ListAPITokensRequest, opts ...grpc.CallOption) (*authv1.ListAPITokensResponse, error)
	RevokeAPIToken(ctx context.Context, in *authv1.RevokeAPITokenRequest, opts ...grpc.CallOption) (*authv1.RevokeAPITokenResponse, error)
	ValidateAPIToken(ctx context.Context, in *authv1.ValidateAPITokenRequest, opts ...grpc.CallOption) (*authv1.ValidateAPITokenResponse, error)
	ListAuditEvents(ctx context.Context, in *authv1.ListAuditEventsRequest, opts ...grpc.CallOption) (*authv1.ListAuditEventsResponse, error)
}

// UserDTO represents user profile information returned upon authentication.
type UserDTO struct {
	ID          string `json:"id"`
	Email       string `json:"email"`
	DisplayName string `json:"display_name"`
	Status      string `json:"status"`
}

// LoginResponseDTO represents the successful client login response JSON schema.
type LoginResponseDTO struct {
	AccessToken  string  `json:"access_token"`
	RefreshToken string  `json:"refresh_token"`
	TokenType    string  `json:"token_type"`
	ExpiresIn    int32   `json:"expires_in"`
	User         UserDTO `json:"user"`
}

// RegisterResponseDTO represents the successful client registration response JSON schema.
type RegisterResponseDTO struct {
	UserID      string `json:"user_id"`
	Email       string `json:"email"`
	DisplayName string `json:"display_name"`
	Status      string `json:"status"`
	CreatedAt   string `json:"created_at"`
}

// RefreshResponseDTO represents the successful client refresh response JSON schema.
type RefreshResponseDTO struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int32  `json:"expires_in"`
}

// LogoutResponseDTO represents the successful client logout response JSON schema.
type LogoutResponseDTO struct {
	Message string `json:"message"`
}

// VerifyEmailResponseDTO represents the successful client email verification response JSON schema.
type VerifyEmailResponseDTO struct {
	Message string `json:"message"`
}

// MeResponseDTO represents the authenticated user profile returned by GET /api/v1/me.
type MeResponseDTO struct {
	ID              string `json:"id,omitempty"`
	UserID          string `json:"user_id"`
	SessionID       string `json:"session_id,omitempty"`
	Kind            string `json:"kind"`
	Email           string `json:"email,omitempty"`
	DisplayName     string `json:"display_name,omitempty"`
	AvatarURL       string `json:"avatar_url,omitempty"`
	Status          string `json:"status,omitempty"`
	EmailVerified   bool   `json:"email_verified"`
	EmailVerifiedAt string `json:"email_verified_at,omitempty"`
	CreatedAt       string `json:"created_at,omitempty"`
}

// SessionInfoDTO represents an active session entry returned by GET /api/v1/auth/sessions.
type SessionInfoDTO struct {
	ID         string `json:"id"`
	UserAgent  string `json:"user_agent,omitempty"`
	IPAddress  string `json:"ip_address,omitempty"`
	CreatedAt  string `json:"created_at"`
	LastSeenAt string `json:"last_seen_at"`
	ExpiresAt  string `json:"expires_at"`
	Current    bool   `json:"current"`
}

// ListSessionsResponseDTO represents the response from GET /api/v1/auth/sessions.
type ListSessionsResponseDTO struct {
	Sessions []SessionInfoDTO `json:"sessions"`
}

// OrganizationDTO represents an organization returned by the gateway.
type OrganizationDTO struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Slug      string `json:"slug"`
	RoleID    string `json:"role_id,omitempty"`
	CreatedAt string `json:"created_at,omitempty"`
	UpdatedAt string `json:"updated_at,omitempty"`
}

// APITokenDTO represents an API token returned by the gateway.
type APITokenDTO struct {
	ID              string   `json:"id"`
	OrgID           string   `json:"org_id"`
	CreatedByUserID string   `json:"created_by_user_id,omitempty"`
	Name            string   `json:"name"`
	TokenPrefix     string   `json:"token_prefix"`
	Permissions     []string `json:"permissions"`
	ExpiresAt       string   `json:"expires_at,omitempty"`
	LastUsedAt      string   `json:"last_used_at,omitempty"`
	CreatedAt       string   `json:"created_at,omitempty"`
}

// CreateAPITokenResponseDTO represents the response from POST /api/v1/orgs/{id}/tokens.
type CreateAPITokenResponseDTO struct {
	Token  APITokenDTO `json:"token"`
	Secret string      `json:"secret"`
}

// AuditEventDTO represents an audit event item returned by GET /api/v1/orgs/{id}/audit.
type AuditEventDTO struct {
	ID           string         `json:"id"`
	OrgID        string         `json:"org_id"`
	ActorUserID  string         `json:"actor_user_id,omitempty"`
	ActorType    string         `json:"actor_type"`
	Action       string         `json:"action"`
	ResourceType string         `json:"resource_type"`
	ResourceID   string         `json:"resource_id"`
	Metadata     map[string]any `json:"metadata,omitempty"`
	CreatedAt    string         `json:"created_at,omitempty"`
}

// ListAuditEventsResponseDTO represents the response from GET /api/v1/orgs/{id}/audit.
type ListAuditEventsResponseDTO struct {
	Events []AuditEventDTO `json:"events"`
}

// ErrorResponseDTO represents standard error response JSON format.
type ErrorResponseDTO struct {
	Error string `json:"error"`
	Code  string `json:"code,omitempty"`
	// RequestID echoes X-Request-ID (set by the request-id middleware) for support correlation.
	RequestID string `json:"request_id,omitempty"`
}

// Handler handles HTTP requests for the API Gateway.
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

func (h *Handler) grpcContext(r *http.Request, timeout time.Duration) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithTimeout(r.Context(), timeout)
	pairs := make([]string, 0, 6)
	if reqID := middleware.RequestIDFromContext(r.Context()); reqID != "" {
		pairs = append(pairs, "x-request-id", reqID)
	}
	if ip := extractClientIP(r); ip != "" {
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

func isDevEnv(env string) bool {
	return strings.EqualFold(env, "dev") || strings.EqualFold(env, "development")
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

const githubOAuthCookieName = "kr0n_gh_oauth"

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
		ClientIp:     extractClientIP(r),
	})
	if err != nil {
		h.writeGRPCError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, LoginResponseDTO{
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

func (h *Handler) writeGRPCError(w http.ResponseWriter, err error) {
	st, ok := status.FromError(err)
	if !ok {
		h.writeError(w, http.StatusInternalServerError, "internal server error", "INTERNAL_ERROR")
		return
	}
	switch st.Code() {
	case codes.InvalidArgument:
		h.writeError(w, http.StatusBadRequest, st.Message(), "INVALID_ARGUMENT")
	case codes.Unauthenticated:
		h.writeError(w, http.StatusUnauthorized, st.Message(), "UNAUTHORIZED")
	case codes.PermissionDenied:
		h.writeError(w, http.StatusForbidden, st.Message(), "FORBIDDEN")
	case codes.NotFound:
		h.writeError(w, http.StatusNotFound, st.Message(), "NOT_FOUND")
	case codes.AlreadyExists:
		h.writeError(w, http.StatusConflict, st.Message(), "ALREADY_EXISTS")
	case codes.FailedPrecondition:
		if strings.Contains(strings.ToLower(st.Message()), "not configured") {
			h.writeError(w, http.StatusServiceUnavailable, st.Message(), "not_configured")
		} else {
			h.writeError(w, http.StatusConflict, st.Message(), "FAILED_PRECONDITION")
		}
	case codes.DeadlineExceeded:
		h.writeError(w, http.StatusGatewayTimeout, "authentication service timeout", "GATEWAY_TIMEOUT")
	case codes.Unavailable:
		h.writeError(w, http.StatusServiceUnavailable, "authentication service unavailable", "SERVICE_UNAVAILABLE")
	default:
		h.writeError(w, http.StatusInternalServerError, "internal server error", "INTERNAL_ERROR")
	}
}

func extractClientIP(r *http.Request) string {
	if ip := middleware.ClientIPFromContext(r.Context()); ip != "" {
		return ip
	}
	// RemoteAddr has the form host:port
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil && host != "" {
		return host
	}
	return r.RemoteAddr
}

func (h *Handler) writeError(w http.ResponseWriter, statusCode int, message, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(ErrorResponseDTO{
		Error:     message,
		Code:      code,
		RequestID: w.Header().Get("X-Request-ID"),
	})
}
