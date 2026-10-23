package grpc

import (
	"context"
	"errors"
	"log"
	"net"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"strings"

	authv1 "github.com/skxm03/kr0n-backend/control-plane/gen/auth/v1"
	"github.com/skxm03/kr0n-backend/control-plane/internal/auth/session"
	"github.com/skxm03/kr0n-backend/control-plane/internal/auth/user"
	"github.com/skxm03/kr0n-backend/control-plane/internal/auth/verification"
)

// RegistrationService defines the domain interface required for user registration.
type RegistrationService interface {
	Register(ctx context.Context, params user.RegisterParams) (*user.User, error)
}

// SessionService defines the domain interface required for authentication, token rotation, and revocation.
type SessionService interface {
	Login(ctx context.Context, params session.LoginParams) (*session.LoginResult, error)
	Refresh(ctx context.Context, rawRefreshToken string) (*session.RefreshResult, error)
	Logout(ctx context.Context, rawRefreshToken string) error
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

// Server implements authv1.AuthServiceServer.
type Server struct {
	authv1.UnimplementedAuthServiceServer
	regService          RegistrationService
	sessionService      SessionService
	verificationService VerificationService
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

	u, err := s.regService.Register(ctx, user.RegisterParams{
		Email:       req.GetEmail(),
		Password:    req.GetPassword(),
		DisplayName: req.GetDisplayName(),
	})
	if err != nil {
		switch {
		case errors.Is(err, user.ErrEmailAlreadyExists):
			return nil, status.Error(codes.AlreadyExists, "email already registered")
		case errors.Is(err, user.ErrInvalidEmail),
			errors.Is(err, user.ErrInvalidPassword),
			errors.Is(err, user.ErrInvalidDisplayName):
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
	}, nil
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
	}

	var clientIP *net.IP
	if rawIP := req.GetClientIp(); rawIP != "" {
		if parsed := net.ParseIP(rawIP); parsed != nil {
			clientIP = &parsed
		}
	}

	res, err := s.sessionService.Login(ctx, session.LoginParams{
		Email:     req.GetEmail(),
		Password:  req.GetPassword(),
		UserAgent: userAgent,
		ClientIP:  clientIP,
	})
	if err != nil {
		switch {
		case errors.Is(err, user.ErrInvalidCredentials):
			return nil, status.Error(codes.Unauthenticated, "invalid email or password")
		case errors.Is(err, user.ErrUserNotActive):
			return nil, status.Error(codes.PermissionDenied, "user account is not active")
		case errors.Is(err, context.DeadlineExceeded):
			return nil, status.Error(codes.DeadlineExceeded, "deadline exceeded")
		case errors.Is(err, context.Canceled):
			return nil, status.Error(codes.Canceled, "request canceled")
		default:
			log.Printf("internal login error: %v", err)
			return nil, status.Error(codes.Internal, "internal server error")
		}
	}

	return &authv1.LoginResponse{
		AccessToken:  res.AccessToken,
		RefreshToken: res.RefreshToken,
		TokenType:    res.TokenType,
		ExpiresIn:    int64(res.ExpiresIn.Seconds()),
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
		case errors.Is(err, session.ErrInvalidRefreshToken),
			errors.Is(err, session.ErrSessionNotFound),
			errors.Is(err, session.ErrSessionRevoked),
			errors.Is(err, session.ErrSessionExpired):
			return nil, status.Error(codes.Unauthenticated, "invalid refresh token")
		case errors.Is(err, user.ErrUserNotActive):
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
		ExpiresIn:    int64(res.ExpiresIn.Seconds()),
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

	err := s.sessionService.Logout(ctx, req.GetRefreshToken())
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

	return &authv1.LogoutResponse{}, nil
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
		case errors.Is(err, verification.ErrInvalidToken):
			return nil, status.Error(codes.InvalidArgument, "invalid or expired verification token")
		case errors.Is(err, verification.ErrUserNotFound):
			return nil, status.Error(codes.InvalidArgument, "invalid or expired verification token")
		case errors.Is(err, verification.ErrUserNotActive):
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

	return &authv1.VerifyEmailResponse{}, nil
}
