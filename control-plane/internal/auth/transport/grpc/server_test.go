package grpc

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	authv1 "github.com/skxm03/kr0n-backend/control-plane/gen/auth/v1"
	"github.com/skxm03/kr0n-backend/control-plane/internal/auth/user"
)

type mockRegistrationService struct {
	registerFunc func(ctx context.Context, params user.RegisterParams) (*user.User, error)
}

func (m *mockRegistrationService) Register(ctx context.Context, params user.RegisterParams) (*user.User, error) {
	if m.registerFunc != nil {
		return m.registerFunc(ctx, params)
	}
	return nil, nil
}

func TestServer_Register_Success(t *testing.T) {
	expectedID := uuid.New()
	expectedTime := time.Date(2026, 9, 30, 10, 0, 0, 0, time.UTC)

	mockSvc := &mockRegistrationService{
		registerFunc: func(ctx context.Context, params user.RegisterParams) (*user.User, error) {
			return &user.User{
				ID:          expectedID,
				Email:       params.Email,
				DisplayName: params.DisplayName,
				Status:      user.StatusActive,
				CreatedAt:   expectedTime,
				UpdatedAt:   expectedTime,
			}, nil
		},
	}

	server := NewServer(mockSvc)
	resp, err := server.Register(context.Background(), &authv1.RegisterRequest{
		Email:       "test@kr0n.dev",
		Password:    "ValidPassword123!",
		DisplayName: "Test User",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp.GetUserId() != expectedID.String() {
		t.Fatalf("expected user ID %s, got %s", expectedID.String(), resp.GetUserId())
	}
	if resp.GetEmail() != "test@kr0n.dev" {
		t.Fatalf("expected email %q, got %q", "test@kr0n.dev", resp.GetEmail())
	}
	if resp.GetDisplayName() != "Test User" {
		t.Fatalf("expected display name %q, got %q", "Test User", resp.GetDisplayName())
	}
	if resp.GetStatus() != "active" {
		t.Fatalf("expected status active, got %s", resp.GetStatus())
	}
	if resp.GetCreatedAt().AsTime() != expectedTime {
		t.Fatalf("expected created_at %v, got %v", expectedTime, resp.GetCreatedAt().AsTime())
	}
}

func TestServer_Register_NilRequest(t *testing.T) {
	server := NewServer(&mockRegistrationService{})
	_, err := server.Register(context.Background(), nil)
	if err == nil {
		t.Fatal("expected error on nil request, got nil")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("expected gRPC status error, got %T", err)
	}
	if st.Code() != codes.InvalidArgument {
		t.Fatalf("expected codes.InvalidArgument, got %v", st.Code())
	}
}

func TestServer_Register_DuplicateEmailError(t *testing.T) {
	mockSvc := &mockRegistrationService{
		registerFunc: func(ctx context.Context, params user.RegisterParams) (*user.User, error) {
			return nil, user.ErrEmailAlreadyExists
		},
	}

	server := NewServer(mockSvc)
	_, err := server.Register(context.Background(), &authv1.RegisterRequest{
		Email:       "existing@kr0n.dev",
		Password:    "ValidPassword123!",
		DisplayName: "Existing",
	})
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("expected gRPC status error, got %T", err)
	}
	if st.Code() != codes.AlreadyExists {
		t.Fatalf("expected codes.AlreadyExists, got %v", st.Code())
	}
	if st.Message() != "email already registered" {
		t.Fatalf("expected message 'email already registered', got %q", st.Message())
	}
}

func TestServer_Register_InvalidArguments(t *testing.T) {
	mockSvc := &mockRegistrationService{
		registerFunc: func(ctx context.Context, params user.RegisterParams) (*user.User, error) {
			return nil, user.ErrInvalidPassword
		},
	}

	server := NewServer(mockSvc)
	_, err := server.Register(context.Background(), &authv1.RegisterRequest{
		Email:       "test@kr0n.dev",
		Password:    "short",
		DisplayName: "Test",
	})
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("expected gRPC status error, got %T", err)
	}
	if st.Code() != codes.InvalidArgument {
		t.Fatalf("expected codes.InvalidArgument, got %v", st.Code())
	}
}

func TestServer_Register_InternalErrorMasked(t *testing.T) {
	mockSvc := &mockRegistrationService{
		registerFunc: func(ctx context.Context, params user.RegisterParams) (*user.User, error) {
			return nil, errors.New("sensitive database connection pool exhaustion at 10.0.1.5")
		},
	}

	server := NewServer(mockSvc)
	_, err := server.Register(context.Background(), &authv1.RegisterRequest{
		Email:       "test@kr0n.dev",
		Password:    "ValidPassword123!",
		DisplayName: "Test",
	})
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("expected gRPC status error, got %T", err)
	}
	if st.Code() != codes.Internal {
		t.Fatalf("expected codes.Internal, got %v", st.Code())
	}
	if st.Message() != "internal server error" {
		t.Fatalf("expected masked error 'internal server error', got %q", st.Message())
	}
}
