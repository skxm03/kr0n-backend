package grpc

import (
	"context"
	"errors"
	"log"
	"net"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	authv1 "github.com/skxm03/kr0n-backend/control-plane/gen/auth/v1"
	"github.com/skxm03/kr0n-backend/control-plane/internal/auth/session"
	"github.com/skxm03/kr0n-backend/control-plane/internal/auth/user"
)

// RegistrationService defines the domain interface required for user registration.
type RegistrationService interface {
	Register(ctx context.Context, params user.RegisterParams) (*user.User, error)
}

// LoginService defines the domain interface required for user authentication and session creation.
type LoginService interface {
	Login(ctx context.Context, params session.LoginParams) (*session.LoginResult, error)
}

// Server implements authv1.AuthServiceServer.
type Server struct {
	authv1.UnimplementedAuthServiceServer
	regService   RegistrationService
	loginService LoginService
}

// NewServer creates a new gRPC Server instance.
func NewServer(regService RegistrationService, loginService LoginService) *Server {
	return &Server{
		regService:   regService,
		loginService: loginService,
	}
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

	if s.loginService == nil {
		return nil, status.Error(codes.Unimplemented, "login service not configured")
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

	res, err := s.loginService.Login(ctx, session.LoginParams{
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
