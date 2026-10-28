package handlers

import (
	"context"
	"errors"
	"log"
	"net"
	"strings"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	authv1 "github.com/skxm03/kr0n-backend/control-plane/gen/auth/v1"
	"github.com/skxm03/kr0n-backend/control-plane/internal/auth/jwtkeys"
	"github.com/skxm03/kr0n-backend/control-plane/internal/auth/oauth"
	"github.com/skxm03/kr0n-backend/control-plane/internal/auth/repository"
	"github.com/skxm03/kr0n-backend/control-plane/internal/auth/service"
)

// GitHubOAuthProvider defines the contract for GitHub OAuth 2.0 + PKCE operations.
type GitHubOAuthProvider interface {
	Configured() bool
	Start() (authorizeURL, state, codeVerifier string, err error)
	ExchangeAndFetchProfile(ctx context.Context, code, codeVerifier string) (*repository.OAuthProfile, error)
}

// RegistrationService defines user registration, account lifecycle, profile, and OAuth operations (satisfied by *service.UserService).
type RegistrationService interface {
	Register(ctx context.Context, params service.RegisterParams) (*repository.User, error)
	ResendVerification(ctx context.Context, rawEmail string) error
	RequestPasswordReset(ctx context.Context, rawEmail string) error
	ConfirmPasswordReset(ctx context.Context, rawToken, newPassword string) (uuid.UUID, error)
	ChangePassword(ctx context.Context, userID uuid.UUID, currentPassword, newPassword string, currentSessionID *uuid.UUID) error
	GetProfile(ctx context.Context, userID uuid.UUID) (*repository.User, error)
	ResolveOAuthUser(ctx context.Context, profile repository.OAuthProfile) (*repository.User, error)
}

// SessionService defines authentication, token rotation, logout, and session lifecycle operations (satisfied by *service.SessionService).
type SessionService interface {
	Login(ctx context.Context, params service.LoginParams) (*service.LoginResult, error)
	Refresh(ctx context.Context, rawRefreshToken string) (*service.RefreshResult, error)
	Logout(ctx context.Context, rawRefreshToken string) (*repository.Session, error)
	ListSessions(ctx context.Context, userID uuid.UUID) ([]repository.Session, error)
	RevokeSession(ctx context.Context, userID, sessionID uuid.UUID) error
	CreateSessionForUser(ctx context.Context, authenticatedUser *repository.User, userAgent *string, clientIP *net.IP) (*service.LoginResult, error)
}

// VerificationService defines the domain interface required for email verification.
type VerificationService interface {
	VerifyEmail(ctx context.Context, rawToken string) error
}

// Option configures Server.
type Option func(*Server)

// WithVerificationService configures the verification service for Server.
func WithVerificationService(vs VerificationService) Option {
	return func(s *Server) {
		s.verificationService = vs
	}
}

// WithJWKS configures the public JSON Web Key Set served by GetJWKS.
func WithJWKS(keys ...jwtkeys.JWK) Option {
	return func(s *Server) {
		s.jwks = append([]jwtkeys.JWK(nil), keys...)
	}
}

// WithGitHubOAuth configures the GitHub OAuth 2.0 + PKCE provider for Server.
func WithGitHubOAuth(gh GitHubOAuthProvider) Option {
	return func(s *Server) {
		s.githubOAuth = gh
	}
}

// WithOrgService configures the organization, RBAC, and API token service for Server.
func WithOrgService(orgSvc *service.OrgService) Option {
	return func(s *Server) {
		s.orgService = orgSvc
	}
}

// WithAuditService configures the append-only audit service for Server.
func WithAuditService(auditSvc *service.AuditService) Option {
	return func(s *Server) {
		s.auditService = auditSvc
	}
}

// WithServiceAuthConfig configures the service-to-service authentication policy for Server.
func WithServiceAuthConfig(cfg ServiceAuthConfig) Option {
	return func(s *Server) {
		s.serviceAuth = cfg
	}
}

// Server implements authv1.AuthServiceServer.
type Server struct {
	authv1.UnimplementedAuthServiceServer
	regService          RegistrationService
	sessionService      SessionService
	verificationService VerificationService
	jwks                []jwtkeys.JWK
	githubOAuth         GitHubOAuthProvider
	orgService          *service.OrgService
	auditService        *service.AuditService
	serviceAuth         ServiceAuthConfig
}

func (s *Server) recordAudit(ctx context.Context, ev repository.AuditEvent) {
	if s.auditService == nil {
		return
	}
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		if ev.IPAddress == nil {
			if ips := md.Get("x-client-ip"); len(ips) > 0 && ips[0] != "" {
				ip := net.ParseIP(ips[0])
				if ip != nil {
					ev.IPAddress = &ip
				}
			}
		}
		if ev.UserAgent == nil {
			if uas := md.Get("x-user-agent"); len(uas) > 0 && uas[0] != "" {
				ua := uas[0]
				ev.UserAgent = &ua
			}
		}
		if reqIDs := md.Get("x-request-id"); len(reqIDs) > 0 && reqIDs[0] != "" {
			if ev.Metadata == nil {
				ev.Metadata = map[string]any{}
			}
			if _, exists := ev.Metadata["request_id"]; !exists {
				ev.Metadata["request_id"] = reqIDs[0]
			}
		}
	}
	if err := s.auditService.Record(ctx, ev); err != nil {
		log.Printf("audit event write error (%s): %v", ev.Action, err)
	}
}

func getMetadata(ctx context.Context) (metadata.MD, bool) {
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		return md, true
	}
	return metadata.FromOutgoingContext(ctx)
}

func (s *Server) extractUserID(ctx context.Context, explicit string) (uuid.UUID, error) {
	if raw := strings.TrimSpace(explicit); raw != "" {
		uid, err := uuid.Parse(raw)
		if err != nil {
			return uuid.Nil, status.Error(codes.InvalidArgument, "invalid user_id")
		}
		return uid, nil
	}
	if md, ok := getMetadata(ctx); ok {
		if vals := md.Get("x-caller-user-id"); len(vals) > 0 && strings.TrimSpace(vals[0]) != "" {
			uid, err := uuid.Parse(strings.TrimSpace(vals[0]))
			if err != nil {
				return uuid.Nil, status.Error(codes.InvalidArgument, "invalid user_id in metadata")
			}
			return uid, nil
		}
	}
	return uuid.Nil, status.Error(codes.Unauthenticated, "authentication required: user_id missing")
}

func (s *Server) extractSessionID(ctx context.Context, explicit string) (*uuid.UUID, error) {
	if raw := strings.TrimSpace(explicit); raw != "" {
		parsed, err := uuid.Parse(raw)
		if err != nil {
			return nil, status.Error(codes.InvalidArgument, "invalid session_id")
		}
		return &parsed, nil
	}
	if md, ok := getMetadata(ctx); ok {
		if vals := md.Get("x-caller-session-id"); len(vals) > 0 && strings.TrimSpace(vals[0]) != "" {
			if parsed, err := uuid.Parse(strings.TrimSpace(vals[0])); err == nil {
				return &parsed, nil
			}
		}
	}
	return nil, nil
}

// NewServer creates a new gRPC Server instance.
func NewServer(regService RegistrationService, sessionService SessionService, opts ...Option) *Server {
	s := &Server{
		regService:     regService,
		sessionService: sessionService,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// Register processes user registration requests over gRPC.
func (s *Server) Register(ctx context.Context, req *authv1.RegisterRequest) (*authv1.RegisterResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request body cannot be empty")
	}

	u, err := s.regService.Register(ctx, service.RegisterParams{
		Email:       req.GetEmail(),
		Password:    req.GetPassword(),
		DisplayName: req.GetDisplayName(),
	})
	if err != nil {
		switch {
		case errors.Is(err, repository.ErrEmailAlreadyExists):
			return nil, status.Error(codes.AlreadyExists, "email already registered")
		case errors.Is(err, repository.ErrInvalidEmail),
			errors.Is(err, repository.ErrInvalidPassword),
			errors.Is(err, repository.ErrInvalidDisplayName):
			return nil, status.Error(codes.InvalidArgument, err.Error())
		case errors.Is(err, context.DeadlineExceeded):
			return nil, status.Error(codes.DeadlineExceeded, "deadline exceeded")
		case errors.Is(err, context.Canceled):
			return nil, status.Error(codes.Canceled, "request canceled")
		default:
			log.Printf("internal registration error: %v", err)
			return nil, status.Error(codes.Internal, "internal server error")
		}
	}

	return &authv1.RegisterResponse{
		UserId:      u.ID.String(),
		Email:       u.Email,
		DisplayName: u.DisplayName,
		Status:      string(u.Status),
		CreatedAt:   timestamppb.New(u.CreatedAt),
	}, s.auditAfterRegister(ctx, u)
}

func (s *Server) auditAfterRegister(ctx context.Context, u *repository.User) error {
	uid := u.ID
	s.recordAudit(ctx, repository.AuditEvent{
		ActorUserID:  &uid,
		ActorType:    repository.ActorTypeUser,
		Action:       "auth.registered",
		ResourceType: "user",
		ResourceID:   uid.String(),
		Metadata:     map[string]any{"email": u.Email},
	})
	return nil
}

// Login processes user authentication and token issuance requests over gRPC.
func (s *Server) Login(ctx context.Context, req *authv1.LoginRequest) (*authv1.LoginResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request body cannot be empty")
	}

	if s.sessionService == nil {
		return nil, status.Error(codes.Unimplemented, "session service not configured")
	}

	var userAgent *string
	if ua := req.GetUserAgent(); ua != "" {
		userAgent = &ua
	} else if md, ok := getMetadata(ctx); ok {
		if uas := md.Get("x-user-agent"); len(uas) > 0 && uas[0] != "" {
			userAgent = &uas[0]
		}
	}

	var clientIP *net.IP
	if rawIP := req.GetClientIp(); rawIP != "" {
		if parsed := net.ParseIP(rawIP); parsed != nil {
			clientIP = &parsed
		}
	} else if md, ok := getMetadata(ctx); ok {
		if ips := md.Get("x-client-ip"); len(ips) > 0 && ips[0] != "" {
			if parsed := net.ParseIP(ips[0]); parsed != nil {
				clientIP = &parsed
			}
		}
	}

	res, err := s.sessionService.Login(ctx, service.LoginParams{
		Email:     req.GetEmail(),
		Password:  req.GetPassword(),
		UserAgent: userAgent,
		ClientIP:  clientIP,
	})
	if err != nil {
		s.recordAudit(ctx, repository.AuditEvent{
			ActorType:    repository.ActorTypeUser,
			Action:       "auth.login_failed",
			ResourceType: "user",
			IPAddress:    clientIP,
			UserAgent:    userAgent,
			Metadata:     map[string]any{"email": strings.ToLower(strings.TrimSpace(req.GetEmail()))},
		})
		switch {
		case errors.Is(err, repository.ErrInvalidCredentials):
			return nil, status.Error(codes.Unauthenticated, "invalid email or password")
		case errors.Is(err, repository.ErrUserNotActive):
			return nil, status.Error(codes.PermissionDenied, "user account is not active")
		case errors.Is(err, repository.ErrEmailNotVerified):
			return nil, status.Error(codes.PermissionDenied, "email address is not verified")
		case errors.Is(err, context.DeadlineExceeded):
			return nil, status.Error(codes.DeadlineExceeded, "deadline exceeded")
		case errors.Is(err, context.Canceled):
			return nil, status.Error(codes.Canceled, "request canceled")
		default:
			log.Printf("internal login error: %v", err)
			return nil, status.Error(codes.Internal, "internal server error")
		}
	}

	uid := res.User.ID
	s.recordAudit(ctx, repository.AuditEvent{
		ActorUserID:  &uid,
		ActorType:    repository.ActorTypeUser,
		Action:       "auth.login_succeeded",
		ResourceType: "session",
		ResourceID:   uid.String(),
		IPAddress:    clientIP,
		UserAgent:    userAgent,
	})

	return &authv1.LoginResponse{
		AccessToken:  res.AccessToken,
		RefreshToken: res.RefreshToken,
		TokenType:    res.TokenType,
		ExpiresIn:    int32(res.ExpiresIn.Seconds()),
		User: &authv1.LoginUser{
			Id:          res.User.ID.String(),
			Email:       res.User.Email,
			DisplayName: res.User.DisplayName,
			Status:      string(res.User.Status),
		},
	}, nil
}

// Refresh processes token refresh and rotation requests over gRPC.
func (s *Server) Refresh(ctx context.Context, req *authv1.RefreshRequest) (*authv1.RefreshResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request body cannot be empty")
	}

	if s.sessionService == nil {
		return nil, status.Error(codes.Unimplemented, "session service not configured")
	}

	if req.GetRefreshToken() == "" {
		return nil, status.Error(codes.InvalidArgument, "refresh token is required")
	}

	res, err := s.sessionService.Refresh(ctx, req.GetRefreshToken())
	if err != nil {
		switch {
		case errors.Is(err, repository.ErrInvalidRefreshToken),
			errors.Is(err, repository.ErrSessionNotFound),
			errors.Is(err, repository.ErrSessionRevoked),
			errors.Is(err, repository.ErrSessionExpired):
			return nil, status.Error(codes.Unauthenticated, "invalid refresh token")
		case errors.Is(err, repository.ErrUserNotActive):
			return nil, status.Error(codes.PermissionDenied, "user account is not active")
		case errors.Is(err, context.DeadlineExceeded):
			return nil, status.Error(codes.DeadlineExceeded, "deadline exceeded")
		case errors.Is(err, context.Canceled):
			return nil, status.Error(codes.Canceled, "request canceled")
		default:
			log.Printf("internal refresh error: %v", err)
			return nil, status.Error(codes.Internal, "internal server error")
		}
	}

	return &authv1.RefreshResponse{
		AccessToken:  res.AccessToken,
		RefreshToken: res.RefreshToken,
		TokenType:    res.TokenType,
		ExpiresIn:    int32(res.ExpiresIn.Seconds()),
	}, nil
}

// Logout processes session revocation requests over gRPC.
func (s *Server) Logout(ctx context.Context, req *authv1.LogoutRequest) (*authv1.LogoutResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request body cannot be empty")
	}

	if s.sessionService == nil {
		return nil, status.Error(codes.Unimplemented, "session service not configured")
	}

	if req.GetRefreshToken() == "" {
		return nil, status.Error(codes.InvalidArgument, "refresh token is required")
	}

	sess, err := s.sessionService.Logout(ctx, req.GetRefreshToken())
	if err != nil {
		switch {
		case errors.Is(err, context.DeadlineExceeded):
			return nil, status.Error(codes.DeadlineExceeded, "deadline exceeded")
		case errors.Is(err, context.Canceled):
			return nil, status.Error(codes.Canceled, "request canceled")
		default:
			log.Printf("internal logout error: %v", err)
			return nil, status.Error(codes.Internal, "internal server error")
		}
	}

	var actorID *uuid.UUID
	var resourceID string
	if sess != nil {
		actorID = &sess.UserID
		resourceID = sess.ID.String()
	}

	s.recordAudit(ctx, repository.AuditEvent{
		ActorUserID:  actorID,
		ActorType:    repository.ActorTypeUser,
		Action:       "auth.logout",
		ResourceType: "session",
		ResourceID:   resourceID,
	})
	return &authv1.LogoutResponse{Message: "logged out successfully"}, nil
}

// VerifyEmail processes email verification token validation over gRPC.
func (s *Server) VerifyEmail(ctx context.Context, req *authv1.VerifyEmailRequest) (*authv1.VerifyEmailResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request body cannot be empty")
	}

	if s.verificationService == nil {
		return nil, status.Error(codes.Unimplemented, "verification service not configured")
	}

	token := strings.TrimSpace(req.GetToken())
	if token == "" {
		return nil, status.Error(codes.InvalidArgument, "verification token is required")
	}

	err := s.verificationService.VerifyEmail(ctx, token)
	if err != nil {
		switch {
		case errors.Is(err, repository.ErrInvalidToken):
			return nil, status.Error(codes.InvalidArgument, "invalid or expired verification token")
		case errors.Is(err, repository.ErrUserNotFound):
			return nil, status.Error(codes.InvalidArgument, "invalid or expired verification token")
		case errors.Is(err, repository.ErrUserNotActive):
			return nil, status.Error(codes.PermissionDenied, "user account is not active")
		case errors.Is(err, context.DeadlineExceeded):
			return nil, status.Error(codes.DeadlineExceeded, "deadline exceeded")
		case errors.Is(err, context.Canceled):
			return nil, status.Error(codes.Canceled, "request canceled")
		default:
			log.Printf("internal verification error: %v", err)
			return nil, status.Error(codes.Internal, "internal server error")
		}
	}

	return &authv1.VerifyEmailResponse{Message: "email verified successfully"}, nil
}

// GetJWKS returns the active public signing keys in JSON Web Key Set format.
func (s *Server) GetJWKS(ctx context.Context, req *authv1.GetJWKSRequest) (*authv1.GetJWKSResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request body cannot be empty")
	}
	out := make([]*authv1.JWK, 0, len(s.jwks))
	for _, k := range s.jwks {
		out = append(out, &authv1.JWK{
			Kty: k.Kty,
			Crv: k.Crv,
			Kid: k.Kid,
			Alg: k.Alg,
			Use: k.Use,
			X:   k.X,
		})
	}
	return &authv1.GetJWKSResponse{Keys: out}, nil
}

// ResendVerification issues a new email verification token if the user is active and unverified.
func (s *Server) ResendVerification(ctx context.Context, req *authv1.ResendVerificationRequest) (*authv1.ResendVerificationResponse, error) {
	if req == nil || strings.TrimSpace(req.GetEmail()) == "" {
		return nil, status.Error(codes.InvalidArgument, "email is required")
	}
	if s.regService == nil {
		return nil, status.Error(codes.Unimplemented, "registration service not configured")
	}
	if err := s.regService.ResendVerification(ctx, req.GetEmail()); err != nil {
		if errors.Is(err, repository.ErrInvalidEmail) {
			return nil, status.Error(codes.InvalidArgument, err.Error())
		}
		log.Printf("internal resend verification error: %v", err)
		return nil, status.Error(codes.Internal, "internal server error")
	}
	return &authv1.ResendVerificationResponse{Message: "if the account exists and is unverified, a new verification link has been sent"}, nil
}

// RequestPasswordReset issues a password reset token and dispatches an email if the account exists.
func (s *Server) RequestPasswordReset(ctx context.Context, req *authv1.RequestPasswordResetRequest) (*authv1.RequestPasswordResetResponse, error) {
	if req == nil || strings.TrimSpace(req.GetEmail()) == "" {
		return nil, status.Error(codes.InvalidArgument, "email is required")
	}
	if s.regService == nil {
		return nil, status.Error(codes.Unimplemented, "registration service not configured")
	}
	if err := s.regService.RequestPasswordReset(ctx, req.GetEmail()); err != nil {
		if errors.Is(err, repository.ErrInvalidEmail) {
			return nil, status.Error(codes.InvalidArgument, err.Error())
		}
		log.Printf("internal request password reset error: %v", err)
		return nil, status.Error(codes.Internal, "internal server error")
	}
	return &authv1.RequestPasswordResetResponse{Message: "if an account exists for that email, a password reset link has been sent"}, nil
}

// ConfirmPasswordReset consumes a password reset token and sets the new password.
func (s *Server) ConfirmPasswordReset(ctx context.Context, req *authv1.ConfirmPasswordResetRequest) (*authv1.ConfirmPasswordResetResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request body cannot be empty")
	}
	token := strings.TrimSpace(req.GetToken())
	if token == "" || req.GetNewPassword() == "" {
		return nil, status.Error(codes.InvalidArgument, "token and new_password are required")
	}
	if s.regService == nil {
		return nil, status.Error(codes.Unimplemented, "registration service not configured")
	}
	userID, err := s.regService.ConfirmPasswordReset(ctx, token, req.GetNewPassword())
	if err != nil {
		switch {
		case errors.Is(err, repository.ErrInvalidResetToken):
			return nil, status.Error(codes.InvalidArgument, "invalid or expired password reset token")
		case errors.Is(err, repository.ErrInvalidPassword):
			return nil, status.Error(codes.InvalidArgument, err.Error())
		case errors.Is(err, repository.ErrUserNotActive):
			return nil, status.Error(codes.PermissionDenied, "user account is not active")
		default:
			log.Printf("internal confirm password reset error: %v", err)
			return nil, status.Error(codes.Internal, "internal server error")
		}
	}
	s.recordAudit(ctx, repository.AuditEvent{
		ActorUserID:  &userID,
		ActorType:    repository.ActorTypeUser,
		Action:       "auth.password_reset_confirmed",
		ResourceType: "user",
		ResourceID:   userID.String(),
	})
	return &authv1.ConfirmPasswordResetResponse{Message: "password reset successfully"}, nil
}

// ChangePassword verifies current_password, updates the password, and revokes other sessions.
func (s *Server) ChangePassword(ctx context.Context, req *authv1.ChangePasswordRequest) (*authv1.ChangePasswordResponse, error) {
	if s.serviceAuth.Enabled && !IsTrustedService(ctx) {
		return nil, status.Error(codes.Unauthenticated, "trusted service authentication required")
	}
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request body cannot be empty")
	}
	userID, err := s.extractUserID(ctx, req.GetUserId())
	if err != nil {
		return nil, err
	}
	if req.GetCurrentPassword() == "" || req.GetNewPassword() == "" {
		return nil, status.Error(codes.InvalidArgument, "current_password and new_password are required")
	}
	currentSessID, _ := s.extractSessionID(ctx, req.GetSessionId())

	if s.regService == nil {
		return nil, status.Error(codes.Unimplemented, "registration service not configured")
	}
	if err := s.regService.ChangePassword(ctx, userID, req.GetCurrentPassword(), req.GetNewPassword(), currentSessID); err != nil {
		switch {
		case errors.Is(err, repository.ErrInvalidCredentials):
			return nil, status.Error(codes.Unauthenticated, "invalid current password")
		case errors.Is(err, repository.ErrInvalidPassword):
			return nil, status.Error(codes.InvalidArgument, err.Error())
		case errors.Is(err, repository.ErrUserNotFound):
			return nil, status.Error(codes.NotFound, "user not found")
		case errors.Is(err, repository.ErrUserNotActive):
			return nil, status.Error(codes.PermissionDenied, "user account is not active")
		default:
			log.Printf("internal change password error: %v", err)
			return nil, status.Error(codes.Internal, "internal server error")
		}
	}
	s.recordAudit(ctx, repository.AuditEvent{
		ActorUserID:  &userID,
		ActorType:    repository.ActorTypeUser,
		Action:       "auth.password_changed",
		ResourceType: "user",
		ResourceID:   userID.String(),
	})
	return &authv1.ChangePasswordResponse{Message: "password changed successfully"}, nil
}

// GetMe retrieves the authenticated user's profile.
func (s *Server) GetMe(ctx context.Context, req *authv1.GetMeRequest) (*authv1.GetMeResponse, error) {
	if s.serviceAuth.Enabled && !IsTrustedService(ctx) {
		return nil, status.Error(codes.Unauthenticated, "trusted service authentication required")
	}
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request body cannot be empty")
	}
	userID, err := s.extractUserID(ctx, req.GetUserId())
	if err != nil {
		return nil, err
	}
	if s.regService == nil {
		return nil, status.Error(codes.Unimplemented, "registration service not configured")
	}
	u, err := s.regService.GetProfile(ctx, userID)
	if err != nil {
		if errors.Is(err, repository.ErrUserNotFound) {
			return nil, status.Error(codes.NotFound, "user not found")
		}
		log.Printf("internal get profile error: %v", err)
		return nil, status.Error(codes.Internal, "internal server error")
	}

	resp := &authv1.GetMeResponse{
		Id:            u.ID.String(),
		UserId:        u.ID.String(),
		Email:         u.Email,
		DisplayName:   u.DisplayName,
		Status:        string(u.Status),
		EmailVerified: u.EmailVerifiedAt != nil,
		CreatedAt:     timestamppb.New(u.CreatedAt),
		Kind:          "session",
	}
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		if kinds := md.Get("x-caller-kind"); len(kinds) > 0 && kinds[0] != "" {
			resp.Kind = kinds[0]
		}
		if sess := md.Get("x-caller-session-id"); len(sess) > 0 {
			resp.SessionId = sess[0]
		}
	}
	if u.AvatarURL != nil {
		resp.AvatarUrl = *u.AvatarURL
	}
	if u.EmailVerifiedAt != nil {
		resp.EmailVerifiedAt = timestamppb.New(*u.EmailVerifiedAt)
	}
	return resp, nil
}

// ListSessions returns active sessions for the authenticated user.
func (s *Server) ListSessions(ctx context.Context, req *authv1.ListSessionsRequest) (*authv1.ListSessionsResponse, error) {
	if s.serviceAuth.Enabled && !IsTrustedService(ctx) {
		return nil, status.Error(codes.Unauthenticated, "trusted service authentication required")
	}
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request body cannot be empty")
	}
	userID, err := s.extractUserID(ctx, req.GetUserId())
	if err != nil {
		return nil, err
	}
	if s.sessionService == nil {
		return nil, status.Error(codes.Unimplemented, "session service not configured")
	}
	sessions, err := s.sessionService.ListSessions(ctx, userID)
	if err != nil {
		log.Printf("internal list sessions error: %v", err)
		return nil, status.Error(codes.Internal, "internal server error")
	}
	currentSessID, _ := s.extractSessionID(ctx, "")
	out := make([]*authv1.SessionInfo, 0, len(sessions))
	for _, sess := range sessions {
		info := &authv1.SessionInfo{
			Id:         sess.ID.String(),
			CreatedAt:  timestamppb.New(sess.CreatedAt),
			LastSeenAt: timestamppb.New(sess.LastSeenAt),
			ExpiresAt:  timestamppb.New(sess.ExpiresAt),
			Current:    currentSessID != nil && *currentSessID == sess.ID,
		}
		if sess.UserAgent != nil {
			info.UserAgent = *sess.UserAgent
		}
		if sess.IPAddress != nil {
			info.IpAddress = sess.IPAddress.String()
		}
		out = append(out, info)
	}
	return &authv1.ListSessionsResponse{Sessions: out}, nil
}

// RevokeSession revokes a specific session belonging to the authenticated user.
func (s *Server) RevokeSession(ctx context.Context, req *authv1.RevokeSessionRequest) (*authv1.RevokeSessionResponse, error) {
	if s.serviceAuth.Enabled && !IsTrustedService(ctx) {
		return nil, status.Error(codes.Unauthenticated, "trusted service authentication required")
	}
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request body cannot be empty")
	}
	userID, err := s.extractUserID(ctx, req.GetUserId())
	if err != nil {
		return nil, err
	}
	sessionID, err := uuid.Parse(strings.TrimSpace(req.GetSessionId()))
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid session_id")
	}
	if s.sessionService == nil {
		return nil, status.Error(codes.Unimplemented, "session service not configured")
	}
	if err := s.sessionService.RevokeSession(ctx, userID, sessionID); err != nil {
		if errors.Is(err, repository.ErrSessionNotFound) {
			return nil, status.Error(codes.NotFound, "session not found")
		}
		log.Printf("internal revoke session error: %v", err)
		return nil, status.Error(codes.Internal, "internal server error")
	}
	return &authv1.RevokeSessionResponse{Message: "session revoked successfully"}, nil
}

// StartGitHubOAuth generates a PKCE challenge, state, and GitHub authorize URL.
func (s *Server) StartGitHubOAuth(ctx context.Context, req *authv1.StartGitHubOAuthRequest) (*authv1.StartGitHubOAuthResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request body cannot be empty")
	}
	if s.githubOAuth == nil || !s.githubOAuth.Configured() {
		return nil, status.Error(codes.FailedPrecondition, "github oauth is not configured")
	}
	authURL, state, verifier, err := s.githubOAuth.Start()
	if err != nil {
		if errors.Is(err, oauth.ErrNotConfigured) {
			return nil, status.Error(codes.FailedPrecondition, "github oauth is not configured")
		}
		log.Printf("internal github oauth start error: %v", err)
		return nil, status.Error(codes.Internal, "internal server error")
	}
	return &authv1.StartGitHubOAuthResponse{
		AuthorizeUrl: authURL,
		State:        state,
		CodeVerifier: verifier,
	}, nil
}

// CompleteGitHubOAuth exchanges an OAuth code + PKCE verifier, links/creates the user, and issues a session.
func (s *Server) CompleteGitHubOAuth(ctx context.Context, req *authv1.CompleteGitHubOAuthRequest) (*authv1.CompleteGitHubOAuthResponse, error) {
	if s.serviceAuth.Enabled && !IsTrustedService(ctx) {
		return nil, status.Error(codes.Unauthenticated, "trusted service authentication required")
	}
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request body cannot be empty")
	}
	if s.githubOAuth == nil || !s.githubOAuth.Configured() {
		return nil, status.Error(codes.FailedPrecondition, "github oauth is not configured")
	}
	code := strings.TrimSpace(req.GetCode())
	verifier := strings.TrimSpace(req.GetCodeVerifier())
	if code == "" || verifier == "" {
		return nil, status.Error(codes.InvalidArgument, "code and code_verifier are required")
	}

	if s.regService == nil {
		return nil, status.Error(codes.Unimplemented, "registration service not configured")
	}
	if s.sessionService == nil {
		return nil, status.Error(codes.Unimplemented, "session service not configured")
	}

	profile, err := s.githubOAuth.ExchangeAndFetchProfile(ctx, code, verifier)
	if err != nil {
		switch {
		case errors.Is(err, oauth.ErrNotConfigured):
			return nil, status.Error(codes.FailedPrecondition, "github oauth is not configured")
		case errors.Is(err, repository.ErrOAuthEmailNotVerified):
			return nil, status.Error(codes.PermissionDenied, "github email address is not verified")
		case errors.Is(err, oauth.ErrExchangeFailed):
			return nil, status.Error(codes.Unauthenticated, "github oauth authentication failed")
		default:
			log.Printf("internal github oauth exchange error: %v", err)
			return nil, status.Error(codes.Internal, "internal server error")
		}
	}

	u, err := s.regService.ResolveOAuthUser(ctx, *profile)
	if err != nil {
		switch {
		case errors.Is(err, repository.ErrOAuthEmailNotVerified):
			return nil, status.Error(codes.PermissionDenied, "github email address is not verified")
		case errors.Is(err, repository.ErrUserNotActive):
			return nil, status.Error(codes.PermissionDenied, "user account is not active")
		case errors.Is(err, repository.ErrOAuthAccountConflict):
			return nil, status.Error(codes.AlreadyExists, err.Error())
		default:
			log.Printf("internal github oauth resolve user error: %v", err)
			return nil, status.Error(codes.Internal, "internal server error")
		}
	}

	var userAgent *string
	if ua := req.GetUserAgent(); ua != "" {
		userAgent = &ua
	} else if md, ok := getMetadata(ctx); ok {
		if uas := md.Get("x-user-agent"); len(uas) > 0 && uas[0] != "" {
			userAgent = &uas[0]
		}
	}
	var clientIP *net.IP
	if rawIP := req.GetClientIp(); rawIP != "" {
		if parsed := net.ParseIP(rawIP); parsed != nil {
			clientIP = &parsed
		}
	} else if md, ok := getMetadata(ctx); ok {
		if ips := md.Get("x-client-ip"); len(ips) > 0 && ips[0] != "" {
			if parsed := net.ParseIP(ips[0]); parsed != nil {
				clientIP = &parsed
			}
		}
	}

	res, err := s.sessionService.CreateSessionForUser(ctx, u, userAgent, clientIP)
	if err != nil {
		log.Printf("internal github oauth session error: %v", err)
		return nil, status.Error(codes.Internal, "internal server error")
	}

	uid := res.User.ID
	s.recordAudit(ctx, repository.AuditEvent{
		ActorUserID:  &uid,
		ActorType:    repository.ActorTypeUser,
		Action:       "auth.oauth_github_linked",
		ResourceType: "user",
		ResourceID:   uid.String(),
		IPAddress:    clientIP,
		UserAgent:    userAgent,
		Metadata:     map[string]any{"provider": profile.Provider, "provider_user_id": profile.ProviderUserID},
	})
	return &authv1.CompleteGitHubOAuthResponse{
		AccessToken:  res.AccessToken,
		RefreshToken: res.RefreshToken,
		TokenType:    res.TokenType,
		ExpiresIn:    int32(res.ExpiresIn.Seconds()),
		User: &authv1.LoginUser{
			Id:          res.User.ID.String(),
			Email:       res.User.Email,
			DisplayName: res.User.DisplayName,
			Status:      string(res.User.Status),
		},
	}, nil
}
