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
	"github.com/skxm03/kr0n-backend/control-plane/internal/auth/session"
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

type mockLoginService struct {
	loginFunc func(ctx context.Context, params session.LoginParams) (*session.LoginResult, error)
}

func (m *mockLoginService) Login(ctx context.Context, params session.LoginParams) (*session.LoginResult, error) {
	if m.loginFunc != nil {
		return m.loginFunc(ctx, params)
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

	server := NewServer(mockSvc, nil)
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
	server := NewServer(&mockRegistrationService{}, nil)
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

	server := NewServer(mockSvc, nil)
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

	server := NewServer(mockSvc, nil)
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

	server := NewServer(mockSvc, nil)
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

func TestServer_Login_Success(t *testing.T) {
	expectedUser := &user.User{
		ID:          uuid.New(),
		Email:       "user@kr0n.dev",
		DisplayName: "User",
		Status:      user.StatusActive,
	}

	mockLogin := &mockLoginService{
		loginFunc: func(ctx context.Context, params session.LoginParams) (*session.LoginResult, error) {
			return &session.LoginResult{
				AccessToken:  "access.jwt.token",
				RefreshToken: "opaque_refresh",
				TokenType:    "Bearer",
				ExpiresIn:    15 * time.Minute,
				User:         expectedUser,
			}, nil
		},
	}

	server := NewServer(nil, mockLogin)
	resp, err := server.Login(context.Background(), &authv1.LoginRequest{
		Email:     "user@kr0n.dev",
		Password:  "password",
		UserAgent: "Mozilla",
		ClientIp:  "127.0.0.1",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp.GetAccessToken() != "access.jwt.token" {
		t.Fatalf("unexpected access token: %s", resp.GetAccessToken())
	}
	if resp.GetRefreshToken() != "opaque_refresh" {
		t.Fatalf("unexpected refresh token: %s", resp.GetRefreshToken())
	}
	if resp.GetTokenType() != "Bearer" {
		t.Fatalf("unexpected token type: %s", resp.GetTokenType())
	}
	if resp.GetExpiresIn() != 900 {
		t.Fatalf("expected 900 seconds, got %d", resp.GetExpiresIn())
	}
	if resp.GetUser().GetId() != expectedUser.ID.String() {
		t.Fatalf("unexpected user ID: %s", resp.GetUser().GetId())
	}
}

func TestServer_Login_NilRequest(t *testing.T) {
	server := NewServer(nil, &mockLoginService{})
	_, err := server.Login(context.Background(), nil)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	st, ok := status.FromError(err)
	if !ok || st.Code() != codes.InvalidArgument {
		t.Fatalf("expected InvalidArgument, got %v", err)
	}
}

func TestServer_Login_InvalidCredentials(t *testing.T) {
	mockLogin := &mockLoginService{
		loginFunc: func(ctx context.Context, params session.LoginParams) (*session.LoginResult, error) {
			return nil, user.ErrInvalidCredentials
		},
	}

	server := NewServer(nil, mockLogin)
	_, err := server.Login(context.Background(), &authv1.LoginRequest{
		Email:    "user@kr0n.dev",
		Password: "wrong",
	})
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("expected gRPC status error, got %T", err)
	}
	if st.Code() != codes.Unauthenticated {
		t.Fatalf("expected codes.Unauthenticated, got %v", st.Code())
	}
	if st.Message() != "invalid email or password" {
		t.Fatalf("expected message 'invalid email or password', got %q", st.Message())
	}
}

func TestServer_Login_InactiveUser(t *testing.T) {
	mockLogin := &mockLoginService{
		loginFunc: func(ctx context.Context, params session.LoginParams) (*session.LoginResult, error) {
			return nil, user.ErrUserNotActive
		},
	}

	server := NewServer(nil, mockLogin)
	_, err := server.Login(context.Background(), &authv1.LoginRequest{
		Email:    "inactive@kr0n.dev",
		Password: "password",
	})
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	st, ok := status.FromError(err)
	if !ok || st.Code() != codes.PermissionDenied {
		t.Fatalf("expected codes.PermissionDenied, got %v", err)
	}
}

func TestServer_Login_InternalErrorMasked(t *testing.T) {
	mockLogin := &mockLoginService{
		loginFunc: func(ctx context.Context, params session.LoginParams) (*session.LoginResult, error) {
			return nil, errors.New("sensitive postgres query failure")
		},
	}

	server := NewServer(nil, mockLogin)
	_, err := server.Login(context.Background(), &authv1.LoginRequest{
		Email:    "user@kr0n.dev",
		Password: "password",
	})
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	st, ok := status.FromError(err)
	if !ok || st.Code() != codes.Internal {
		t.Fatalf("expected codes.Internal, got %v", err)
	}
	if st.Message() != "internal server error" {
		t.Fatalf("expected masked error 'internal server error', got %q", st.Message())
	}
}
