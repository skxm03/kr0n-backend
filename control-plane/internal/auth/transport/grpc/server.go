package grpc

import (
	"context"
	"errors"
	"log"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	authv1 "github.com/skxm03/kr0n-backend/control-plane/gen/auth/v1"
	"github.com/skxm03/kr0n-backend/control-plane/internal/auth/user"
)

// RegistrationService defines the domain interface required by the gRPC transport server.
type RegistrationService interface {
	Register(ctx context.Context, params user.RegisterParams) (*user.User, error)
}

// Server implements authv1.AuthServiceServer.
type Server struct {
	authv1.UnimplementedAuthServiceServer
	service RegistrationService
}

// NewServer creates a new gRPC Server instance.
func NewServer(service RegistrationService) *Server {
	return &Server{
		service: service,
	}
}

// Register processes user registration requests over gRPC.
func (s *Server) Register(ctx context.Context, req *authv1.RegisterRequest) (*authv1.RegisterResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request body cannot be empty")
	}

	u, err := s.service.Register(ctx, user.RegisterParams{
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
