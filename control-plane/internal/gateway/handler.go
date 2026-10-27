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

// RegisterRequestDTO represents the client registration request JSON schema.
type RegisterRequestDTO struct {
	Email       string `json:"email"`
	Password    string `json:"password"`
	DisplayName string `json:"display_name"`
}

// RegisterResponseDTO represents the successful client registration response JSON schema.
type RegisterResponseDTO struct {
	UserID      string `json:"user_id"`
	Email       string `json:"email"`
	DisplayName string `json:"display_name"`
	Status      string `json:"status"`
	CreatedAt   string `json:"created_at"`
}

// LoginRequestDTO represents the client login request JSON schema.
type LoginRequestDTO struct {
	Email    string `json:"email"`
	Password string `json:"password"`
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
	ExpiresIn    int64   `json:"expires_in"`
	User         UserDTO `json:"user"`
}

// RefreshRequestDTO represents the client refresh request JSON schema.
type RefreshRequestDTO struct {
	RefreshToken string `json:"refresh_token"`
}

// RefreshResponseDTO represents the successful client refresh response JSON schema.
type RefreshResponseDTO struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
}

// LogoutRequestDTO represents the client logout request JSON schema.
type LogoutRequestDTO struct {
	RefreshToken string `json:"refresh_token"`
}

// LogoutResponseDTO represents the successful client logout response JSON schema.
type LogoutResponseDTO struct {
	Message string `json:"message"`
}

// VerifyEmailRequestDTO represents the client email verification request JSON schema.
type VerifyEmailRequestDTO struct {
	Token string `json:"token"`
}

// VerifyEmailResponseDTO represents the successful client email verification response JSON schema.
type VerifyEmailResponseDTO struct {
	Message string `json:"message"`
}

// EmailRequestDTO represents a request body carrying an email address (resend-verification, password-reset/request).
type EmailRequestDTO struct {
	Email string `json:"email"`
}

// MessageResponseDTO represents a generic message response JSON schema.
type MessageResponseDTO struct {
	Message string `json:"message"`
}

// ConfirmPasswordResetRequestDTO represents the password-reset/confirm request JSON schema.
type ConfirmPasswordResetRequestDTO struct {
	Token       string `json:"token"`
	NewPassword string `json:"new_password"`
}

// ChangePasswordRequestDTO represents the password/change request JSON schema.
type ChangePasswordRequestDTO struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
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

func (h *Handler) decodeJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	contentType := r.Header.Get("Content-Type")
	if !strings.HasPrefix(strings.ToLower(contentType), "application/json") {
		h.writeError(w, http.StatusUnsupportedMediaType, "content-type must be application/json", "UNSUPPORTED_MEDIA_TYPE")
		return false
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1048576)
	if err := json.NewDecoder(r.Body).Decode(dst); err != nil {
		h.writeError(w, http.StatusBadRequest, "invalid request body", "MALFORMED_JSON")
		return false
	}
	return true
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

// Register handles user registration HTTP POST requests.
func (h *Handler) Register(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.writeError(w, http.StatusMethodNotAllowed, "method not allowed", "METHOD_NOT_ALLOWED")
		return
	}
	var req RegisterRequestDTO
	if !h.decodeJSON(w, r, &req) {
		return
	}
	if strings.TrimSpace(req.Email) == "" || req.Password == "" || strings.TrimSpace(req.DisplayName) == "" {
		h.writeError(w, http.StatusBadRequest, "email, password, and display_name are required", "INVALID_ARGUMENT")
		return
	}

	ctx, cancel := h.grpcContext(r, 5*time.Second)
	defer cancel()

	grpcResp, err := h.authClient.Register(ctx, &authv1.RegisterRequest{
		Email:       req.Email,
		Password:    req.Password,
		DisplayName: req.DisplayName,
	})
	if err != nil {
		if st, ok := status.FromError(err); ok && st.Code() == codes.AlreadyExists {
			h.writeError(w, http.StatusConflict, st.Message(), "EMAIL_ALREADY_EXISTS")
			return
		}
		h.writeGRPCError(w, err)
		return
	}

	writeJSON(w, http.StatusCreated, RegisterResponseDTO{
		UserID:      grpcResp.GetUserId(),
		Email:       grpcResp.GetEmail(),
		DisplayName: grpcResp.GetDisplayName(),
		Status:      grpcResp.GetStatus(),
		CreatedAt:   grpcResp.GetCreatedAt().AsTime().Format(time.RFC3339),
	})
}

// Login handles user login HTTP POST requests.
func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.writeError(w, http.StatusMethodNotAllowed, "method not allowed", "METHOD_NOT_ALLOWED")
		return
	}
	var req LoginRequestDTO
	if !h.decodeJSON(w, r, &req) {
		return
	}
	if strings.TrimSpace(req.Email) == "" || req.Password == "" {
		h.writeError(w, http.StatusBadRequest, "email and password are required", "INVALID_ARGUMENT")
		return
	}

	ctx, cancel := h.grpcContext(r, 5*time.Second)
	defer cancel()

	grpcResp, err := h.authClient.Login(ctx, &authv1.LoginRequest{
		Email:     req.Email,
		Password:  req.Password,
		UserAgent: r.UserAgent(),
		ClientIp:  extractClientIP(r),
	})
	if err != nil {
		if st, ok := status.FromError(err); ok {
			switch st.Code() {
			case codes.Unauthenticated:
				h.writeError(w, http.StatusUnauthorized, "invalid email or password", "UNAUTHORIZED")
				return
			case codes.PermissionDenied:
				msg := st.Message()
				if msg == "" {
					msg = "user account is not active"
				}
				h.writeError(w, http.StatusForbidden, msg, "FORBIDDEN")
				return
			}
		}
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

// Refresh handles token rotation HTTP POST requests.
func (h *Handler) Refresh(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.writeError(w, http.StatusMethodNotAllowed, "method not allowed", "METHOD_NOT_ALLOWED")
		return
	}
	var req RefreshRequestDTO
	if !h.decodeJSON(w, r, &req) {
		return
	}
	if strings.TrimSpace(req.RefreshToken) == "" {
		h.writeError(w, http.StatusBadRequest, "refresh_token is required", "INVALID_ARGUMENT")
		return
	}

	ctx, cancel := h.grpcContext(r, 5*time.Second)
	defer cancel()

	grpcResp, err := h.authClient.Refresh(ctx, &authv1.RefreshRequest{
		RefreshToken: req.RefreshToken,
	})
	if err != nil {
		if st, ok := status.FromError(err); ok {
			switch st.Code() {
			case codes.Unauthenticated:
				h.writeError(w, http.StatusUnauthorized, "invalid refresh token", "UNAUTHORIZED")
				return
			case codes.PermissionDenied:
				h.writeError(w, http.StatusForbidden, "user account is not active", "FORBIDDEN")
				return
			}
		}
		h.writeGRPCError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, RefreshResponseDTO{
		AccessToken:  grpcResp.GetAccessToken(),
		RefreshToken: grpcResp.GetRefreshToken(),
		TokenType:    grpcResp.GetTokenType(),
		ExpiresIn:    grpcResp.GetExpiresIn(),
	})
}

// Logout handles session revocation HTTP POST requests.
func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.writeError(w, http.StatusMethodNotAllowed, "method not allowed", "METHOD_NOT_ALLOWED")
		return
	}
	var req LogoutRequestDTO
	if !h.decodeJSON(w, r, &req) {
		return
	}
	if strings.TrimSpace(req.RefreshToken) == "" {
		h.writeError(w, http.StatusBadRequest, "refresh_token is required", "INVALID_ARGUMENT")
		return
	}

	ctx, cancel := h.grpcContext(r, 5*time.Second)
	defer cancel()

	if _, err := h.authClient.Logout(ctx, &authv1.LogoutRequest{
		RefreshToken: req.RefreshToken,
	}); err != nil {
		h.writeGRPCError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, LogoutResponseDTO{
		Message: "logged out successfully",
	})
}

// VerifyEmail handles email verification HTTP POST requests.
func (h *Handler) VerifyEmail(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.writeError(w, http.StatusMethodNotAllowed, "method not allowed", "METHOD_NOT_ALLOWED")
		return
	}
	var req VerifyEmailRequestDTO
	if !h.decodeJSON(w, r, &req) {
		return
	}
	if strings.TrimSpace(req.Token) == "" {
		h.writeError(w, http.StatusBadRequest, "token is required", "INVALID_ARGUMENT")
		return
	}

	ctx, cancel := h.grpcContext(r, 5*time.Second)
	defer cancel()

	if _, err := h.authClient.VerifyEmail(ctx, &authv1.VerifyEmailRequest{
		Token: req.Token,
	}); err != nil {
		h.writeGRPCError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, VerifyEmailResponseDTO{
		Message: "email verified successfully",
	})
}

// ResendVerification handles POST /api/v1/auth/resend-verification.
func (h *Handler) ResendVerification(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.writeError(w, http.StatusMethodNotAllowed, "method not allowed", "METHOD_NOT_ALLOWED")
		return
	}
	var req EmailRequestDTO
	if !h.decodeJSON(w, r, &req) {
		return
	}
	if strings.TrimSpace(req.Email) == "" {
		h.writeError(w, http.StatusBadRequest, "email is required", "INVALID_ARGUMENT")
		return
	}

	ctx, cancel := h.grpcContext(r, 5*time.Second)
	defer cancel()

	if _, err := h.authClient.ResendVerification(ctx, &authv1.ResendVerificationRequest{Email: req.Email}); err != nil {
		h.writeGRPCError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, MessageResponseDTO{
		Message: "if an unverified account exists for that email, a verification link has been sent",
	})
}

// RequestPasswordReset handles POST /api/v1/auth/password-reset/request.
func (h *Handler) RequestPasswordReset(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.writeError(w, http.StatusMethodNotAllowed, "method not allowed", "METHOD_NOT_ALLOWED")
		return
	}
	var req EmailRequestDTO
	if !h.decodeJSON(w, r, &req) {
		return
	}
	if strings.TrimSpace(req.Email) == "" {
		h.writeError(w, http.StatusBadRequest, "email is required", "INVALID_ARGUMENT")
		return
	}

	ctx, cancel := h.grpcContext(r, 5*time.Second)
	defer cancel()

	if _, err := h.authClient.RequestPasswordReset(ctx, &authv1.RequestPasswordResetRequest{Email: req.Email}); err != nil {
		h.writeGRPCError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, MessageResponseDTO{
		Message: "if an account exists for that email, a password reset link has been sent",
	})
}

// ConfirmPasswordReset handles POST /api/v1/auth/password-reset/confirm.
func (h *Handler) ConfirmPasswordReset(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.writeError(w, http.StatusMethodNotAllowed, "method not allowed", "METHOD_NOT_ALLOWED")
		return
	}
	var req ConfirmPasswordResetRequestDTO
	if !h.decodeJSON(w, r, &req) {
		return
	}
	if strings.TrimSpace(req.Token) == "" || req.NewPassword == "" {
		h.writeError(w, http.StatusBadRequest, "token and new_password are required", "INVALID_ARGUMENT")
		return
	}

	ctx, cancel := h.grpcContext(r, 5*time.Second)
	defer cancel()

	if _, err := h.authClient.ConfirmPasswordReset(ctx, &authv1.ConfirmPasswordResetRequest{
		Token:       req.Token,
		NewPassword: req.NewPassword,
	}); err != nil {
		h.writeGRPCError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, MessageResponseDTO{
		Message: "password reset successfully",
	})
}

// ChangePassword handles POST /api/v1/auth/password/change for authenticated users.
func (h *Handler) ChangePassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.writeError(w, http.StatusMethodNotAllowed, "method not allowed", "METHOD_NOT_ALLOWED")
		return
	}
	p, ok := middleware.PrincipalFromContext(r.Context())
	if !ok || p.UserID == "" {
		h.writeError(w, http.StatusUnauthorized, "authentication required", "UNAUTHORIZED")
		return
	}
	var req ChangePasswordRequestDTO
	if !h.decodeJSON(w, r, &req) {
		return
	}
	if req.CurrentPassword == "" || req.NewPassword == "" {
		h.writeError(w, http.StatusBadRequest, "current_password and new_password are required", "INVALID_ARGUMENT")
		return
	}

	ctx, cancel := h.grpcContext(r, 5*time.Second)
	defer cancel()

	if _, err := h.authClient.ChangePassword(ctx, &authv1.ChangePasswordRequest{
		UserId:          p.UserID,
		SessionId:       p.SessionID,
		CurrentPassword: req.CurrentPassword,
		NewPassword:     req.NewPassword,
	}); err != nil {
		h.writeGRPCError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, MessageResponseDTO{
		Message: "password changed successfully",
	})
}

// GetMe handles GET /api/v1/me for authenticated users.
func (h *Handler) GetMe(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.writeError(w, http.StatusMethodNotAllowed, "method not allowed", "METHOD_NOT_ALLOWED")
		return
	}
	p, ok := middleware.PrincipalFromContext(r.Context())
	if !ok || p.UserID == "" {
		h.writeError(w, http.StatusUnauthorized, "authentication required", "UNAUTHORIZED")
		return
	}

	resp := MeResponseDTO{
		ID:        p.UserID,
		UserID:    p.UserID,
		SessionID: p.SessionID,
		Kind:      p.Kind,
	}

	if h.authClient != nil {
		ctx, cancel := h.grpcContext(r, 5*time.Second)
		defer cancel()

		grpcResp, err := h.authClient.GetMe(ctx, &authv1.GetMeRequest{UserId: p.UserID})
		if err != nil {
			h.writeGRPCError(w, err)
			return
		}
		if grpcResp != nil {
			resp.ID = grpcResp.GetId()
			resp.Email = grpcResp.GetEmail()
			resp.DisplayName = grpcResp.GetDisplayName()
			resp.AvatarURL = grpcResp.GetAvatarUrl()
			resp.Status = grpcResp.GetStatus()
			resp.EmailVerified = grpcResp.GetEmailVerified()
			if grpcResp.GetEmailVerifiedAt() != nil {
				resp.EmailVerifiedAt = grpcResp.GetEmailVerifiedAt().AsTime().Format(time.RFC3339)
			}
			if grpcResp.GetCreatedAt() != nil {
				resp.CreatedAt = grpcResp.GetCreatedAt().AsTime().Format(time.RFC3339)
			}
		}
	}

	writeJSON(w, http.StatusOK, resp)
}

// ListSessions handles GET /api/v1/auth/sessions for authenticated users.
func (h *Handler) ListSessions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.writeError(w, http.StatusMethodNotAllowed, "method not allowed", "METHOD_NOT_ALLOWED")
		return
	}
	p, ok := middleware.PrincipalFromContext(r.Context())
	if !ok || p.UserID == "" {
		h.writeError(w, http.StatusUnauthorized, "authentication required", "UNAUTHORIZED")
		return
	}

	ctx, cancel := h.grpcContext(r, 5*time.Second)
	defer cancel()

	grpcResp, err := h.authClient.ListSessions(ctx, &authv1.ListSessionsRequest{UserId: p.UserID})
	if err != nil {
		h.writeGRPCError(w, err)
		return
	}

	sessions := make([]SessionInfoDTO, 0, len(grpcResp.GetSessions()))
	for _, s := range grpcResp.GetSessions() {
		dto := SessionInfoDTO{
			ID:        s.GetId(),
			UserAgent: s.GetUserAgent(),
			IPAddress: s.GetIpAddress(),
			Current:   s.GetId() == p.SessionID,
		}
		if s.GetCreatedAt() != nil {
			dto.CreatedAt = s.GetCreatedAt().AsTime().Format(time.RFC3339)
		}
		if s.GetLastSeenAt() != nil {
			dto.LastSeenAt = s.GetLastSeenAt().AsTime().Format(time.RFC3339)
		}
		if s.GetExpiresAt() != nil {
			dto.ExpiresAt = s.GetExpiresAt().AsTime().Format(time.RFC3339)
		}
		sessions = append(sessions, dto)
	}

	writeJSON(w, http.StatusOK, ListSessionsResponseDTO{Sessions: sessions})
}

// RevokeSession handles DELETE /api/v1/auth/sessions/{id} for authenticated users.
func (h *Handler) RevokeSession(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		h.writeError(w, http.StatusMethodNotAllowed, "method not allowed", "METHOD_NOT_ALLOWED")
		return
	}
	p, ok := middleware.PrincipalFromContext(r.Context())
	if !ok || p.UserID == "" {
		h.writeError(w, http.StatusUnauthorized, "authentication required", "UNAUTHORIZED")
		return
	}

	sessionID := strings.TrimSpace(r.PathValue("id"))
	if sessionID == "" {
		h.writeError(w, http.StatusBadRequest, "session id is required", "INVALID_ARGUMENT")
		return
	}

	ctx, cancel := h.grpcContext(r, 5*time.Second)
	defer cancel()

	if _, err := h.authClient.RevokeSession(ctx, &authv1.RevokeSessionRequest{
		UserId:    p.UserID,
		SessionId: sessionID,
	}); err != nil {
		h.writeGRPCError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, MessageResponseDTO{
		Message: "session revoked successfully",
	})
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
