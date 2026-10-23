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
	"github.com/skxm03/kr0n-backend/control-plane/internal/auth/verification"
)

type mockVerificationService struct {
	verifyEmailFunc func(ctx context.Context, rawToken string) error
}

func (m *mockVerificationService) VerifyEmail(ctx context.Context, rawToken string) error {
	if m.verifyEmailFunc != nil {
		return m.verifyEmailFunc(ctx, rawToken)
	}
	return nil
}

type mockRegistrationService struct {
	registerFunc func(ctx context.Context, params user.RegisterParams) (*user.User, error)
}

func (m *mockRegistrationService) Register(ctx context.Context, params user.RegisterParams) (*user.User, error) {
	if m.registerFunc != nil {
		return m.registerFunc(ctx, params)
	}
	return nil, nil
}

type mockSessionService struct {
	loginFunc   func(ctx context.Context, params session.LoginParams) (*session.LoginResult, error)
	refreshFunc func(ctx context.Context, rawRefreshToken string) (*session.RefreshResult, error)
	logoutFunc  func(ctx context.Context, rawRefreshToken string) error
}

func (m *mockSessionService) Login(ctx context.Context, params session.LoginParams) (*session.LoginResult, error) {
	if m.loginFunc != nil {
		return m.loginFunc(ctx, params)
	}
	return nil, nil
}

func (m *mockSessionService) Refresh(ctx context.Context, rawRefreshToken string) (*session.RefreshResult, error) {
	if m.refreshFunc != nil {
		return m.refreshFunc(ctx, rawRefreshToken)
	}
	return nil, nil
}

func (m *mockSessionService) Logout(ctx context.Context, rawRefreshToken string) error {
	if m.logoutFunc != nil {
		return m.logoutFunc(ctx, rawRefreshToken)
	}
	return nil
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

	mockSvc := &mockSessionService{
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

	server := NewServer(nil, mockSvc)
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
	server := NewServer(nil, &mockSessionService{})
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
	mockSvc := &mockSessionService{
		loginFunc: func(ctx context.Context, params session.LoginParams) (*session.LoginResult, error) {
			return nil, user.ErrInvalidCredentials
		},
	}

	server := NewServer(nil, mockSvc)
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
	mockSvc := &mockSessionService{
		loginFunc: func(ctx context.Context, params session.LoginParams) (*session.LoginResult, error) {
			return nil, user.ErrUserNotActive
		},
	}

	server := NewServer(nil, mockSvc)
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
	mockSvc := &mockSessionService{
		loginFunc: func(ctx context.Context, params session.LoginParams) (*session.LoginResult, error) {
			return nil, errors.New("sensitive postgres query failure")
		},
	}

	server := NewServer(nil, mockSvc)
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

func TestServer_Refresh_Success(t *testing.T) {
	mockSvc := &mockSessionService{
		refreshFunc: func(ctx context.Context, rawRefreshToken string) (*session.RefreshResult, error) {
			if rawRefreshToken != "valid_refresh_token" {
				return nil, session.ErrInvalidRefreshToken
			}
			return &session.RefreshResult{
				AccessToken:  "new_jwt_access",
				RefreshToken: "new_opaque_refresh",
				TokenType:    "Bearer",
				ExpiresIn:    15 * time.Minute,
			}, nil
		},
	}

	server := NewServer(nil, mockSvc)
	resp, err := server.Refresh(context.Background(), &authv1.RefreshRequest{
		RefreshToken: "valid_refresh_token",
	})
	if err != nil {
		t.Fatalf("unexpected error on refresh: %v", err)
	}

	if resp.GetAccessToken() != "new_jwt_access" {
		t.Fatalf("expected new access token, got %s", resp.GetAccessToken())
	}
	if resp.GetRefreshToken() != "new_opaque_refresh" {
		t.Fatalf("expected new refresh token, got %s", resp.GetRefreshToken())
	}
	if resp.GetTokenType() != "Bearer" {
		t.Fatalf("expected Bearer token type, got %s", resp.GetTokenType())
	}
	if resp.GetExpiresIn() != 900 {
		t.Fatalf("expected 900 seconds, got %d", resp.GetExpiresIn())
	}
}

func TestServer_Refresh_NilOrEmptyRequest(t *testing.T) {
	server := NewServer(nil, &mockSessionService{})

	// Nil request
	_, err := server.Refresh(context.Background(), nil)
	if err == nil {
		t.Fatal("expected error on nil request, got nil")
	}
	st, ok := status.FromError(err)
	if !ok || st.Code() != codes.InvalidArgument {
		t.Fatalf("expected InvalidArgument on nil request, got %v", err)
	}

	// Empty token
	_, err = server.Refresh(context.Background(), &authv1.RefreshRequest{RefreshToken: ""})
	if err == nil {
		t.Fatal("expected error on empty token, got nil")
	}
	st, ok = status.FromError(err)
	if !ok || st.Code() != codes.InvalidArgument {
		t.Fatalf("expected InvalidArgument on empty token, got %v", err)
	}
}

func TestServer_Refresh_InvalidOrExpiredOrRevokedToken(t *testing.T) {
	errCases := []struct {
		name     string
		retErr   error
		wantMsg  string
		wantCode codes.Code
	}{
		{
			name:     "invalid token",
			retErr:   session.ErrInvalidRefreshToken,
			wantMsg:  "invalid refresh token",
			wantCode: codes.Unauthenticated,
		},
		{
			name:     "session not found",
			retErr:   session.ErrSessionNotFound,
			wantMsg:  "invalid refresh token",
			wantCode: codes.Unauthenticated,
		},
		{
			name:     "session expired",
			retErr:   session.ErrSessionExpired,
			wantMsg:  "invalid refresh token",
			wantCode: codes.Unauthenticated,
		},
		{
			name:     "session revoked",
			retErr:   session.ErrSessionRevoked,
			wantMsg:  "invalid refresh token",
			wantCode: codes.Unauthenticated,
		},
		{
			name:     "inactive user",
			retErr:   user.ErrUserNotActive,
			wantMsg:  "user account is not active",
			wantCode: codes.PermissionDenied,
		},
	}

	for _, tc := range errCases {
		t.Run(tc.name, func(t *testing.T) {
			mockSvc := &mockSessionService{
				refreshFunc: func(ctx context.Context, rawRefreshToken string) (*session.RefreshResult, error) {
					return nil, tc.retErr
				},
			}
			server := NewServer(nil, mockSvc)
			_, err := server.Refresh(context.Background(), &authv1.RefreshRequest{
				RefreshToken: "test_token",
			})
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			st, ok := status.FromError(err)
			if !ok {
				t.Fatalf("expected gRPC status error, got %T", err)
			}
			if st.Code() != tc.wantCode {
				t.Fatalf("expected code %v, got %v", tc.wantCode, st.Code())
			}
			if st.Message() != tc.wantMsg {
				t.Fatalf("expected message %q, got %q", tc.wantMsg, st.Message())
			}
		})
	}
}

func TestServer_Refresh_InternalErrorMasked(t *testing.T) {
	mockSvc := &mockSessionService{
		refreshFunc: func(ctx context.Context, rawRefreshToken string) (*session.RefreshResult, error) {
			return nil, errors.New("database connection refused")
		},
	}
	server := NewServer(nil, mockSvc)
	_, err := server.Refresh(context.Background(), &authv1.RefreshRequest{
		RefreshToken: "test_token",
	})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	st, ok := status.FromError(err)
	if !ok || st.Code() != codes.Internal {
		t.Fatalf("expected codes.Internal, got %v", err)
	}
	if st.Message() != "internal server error" {
		t.Fatalf("expected 'internal server error', got %q", st.Message())
	}
}

func TestServer_Logout_Success(t *testing.T) {
	var loggedOutToken string
	mockSvc := &mockSessionService{
		logoutFunc: func(ctx context.Context, rawRefreshToken string) error {
			loggedOutToken = rawRefreshToken
			return nil
		},
	}

	server := NewServer(nil, mockSvc)
	resp, err := server.Logout(context.Background(), &authv1.LogoutRequest{
		RefreshToken: "token_to_logout",
	})
	if err != nil {
		t.Fatalf("unexpected error on logout: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if loggedOutToken != "token_to_logout" {
		t.Fatalf("expected logout for token_to_logout, got %s", loggedOutToken)
	}
}

func TestServer_Logout_NilOrEmptyRequest(t *testing.T) {
	server := NewServer(nil, &mockSessionService{})

	// Nil request
	_, err := server.Logout(context.Background(), nil)
	if err == nil {
		t.Fatal("expected error on nil request, got nil")
	}
	st, ok := status.FromError(err)
	if !ok || st.Code() != codes.InvalidArgument {
		t.Fatalf("expected InvalidArgument on nil request, got %v", err)
	}

	// Empty token
	_, err = server.Logout(context.Background(), &authv1.LogoutRequest{RefreshToken: ""})
	if err == nil {
		t.Fatal("expected error on empty token, got nil")
	}
	st, ok = status.FromError(err)
	if !ok || st.Code() != codes.InvalidArgument {
		t.Fatalf("expected InvalidArgument on empty token, got %v", err)
	}
}

func TestServer_Logout_InternalErrorMasked(t *testing.T) {
	mockSvc := &mockSessionService{
		logoutFunc: func(ctx context.Context, rawRefreshToken string) error {
			return errors.New("database failure")
		},
	}

	server := NewServer(nil, mockSvc)
	_, err := server.Logout(context.Background(), &authv1.LogoutRequest{
		RefreshToken: "some_token",
	})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	st, ok := status.FromError(err)
	if !ok || st.Code() != codes.Internal {
		t.Fatalf("expected codes.Internal, got %v", err)
	}
	if st.Message() != "internal server error" {
		t.Fatalf("expected 'internal server error', got %q", st.Message())
	}
}

func TestServer_VerifyEmail_Success(t *testing.T) {
	mockVS := &mockVerificationService{
		verifyEmailFunc: func(ctx context.Context, rawToken string) error {
			if rawToken == "valid_token" {
				return nil
			}
			return verification.ErrInvalidToken
		},
	}

	server := NewServer(nil, nil, WithVerificationService(mockVS))
	resp, err := server.VerifyEmail(context.Background(), &authv1.VerifyEmailRequest{
		Token: "valid_token",
	})
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
}

func TestServer_VerifyEmail_InvalidOrExpiredTokens(t *testing.T) {
	testCases := []struct {
		name string
		err  error
	}{
		{"invalid token", verification.ErrInvalidToken},
		{"expired token", verification.ErrTokenExpired},
		{"already consumed token", verification.ErrTokenAlreadyConsumed},
		{"user not found", verification.ErrUserNotFound},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockVS := &mockVerificationService{
				verifyEmailFunc: func(ctx context.Context, rawToken string) error {
					return tc.err
				},
			}

			server := NewServer(nil, nil, WithVerificationService(mockVS))
			_, err := server.VerifyEmail(context.Background(), &authv1.VerifyEmailRequest{
				Token: "some_token",
			})
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			st, ok := status.FromError(err)
			if !ok || st.Code() != codes.InvalidArgument {
				t.Fatalf("expected codes.InvalidArgument, got %v", err)
			}
			if st.Message() != "invalid or expired verification token" {
				t.Fatalf("expected generic error message 'invalid or expired verification token', got %q", st.Message())
			}
		})
	}
}

func TestServer_VerifyEmail_InactiveUser(t *testing.T) {
	mockVS := &mockVerificationService{
		verifyEmailFunc: func(ctx context.Context, rawToken string) error {
			return verification.ErrUserNotActive
		},
	}

	server := NewServer(nil, nil, WithVerificationService(mockVS))
	_, err := server.VerifyEmail(context.Background(), &authv1.VerifyEmailRequest{
		Token: "some_token",
	})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	st, ok := status.FromError(err)
	if !ok || st.Code() != codes.PermissionDenied {
		t.Fatalf("expected codes.PermissionDenied, got %v", err)
	}
}

func TestServer_VerifyEmail_ValidationErrors(t *testing.T) {
	mockVS := &mockVerificationService{}
	server := NewServer(nil, nil, WithVerificationService(mockVS))

	// Nil request
	_, err := server.VerifyEmail(context.Background(), nil)
	if err == nil {
		t.Fatal("expected error on nil request, got nil")
	}
	st, ok := status.FromError(err)
	if !ok || st.Code() != codes.InvalidArgument {
		t.Fatalf("expected InvalidArgument on nil request, got %v", err)
	}

	// Empty token
	_, err = server.VerifyEmail(context.Background(), &authv1.VerifyEmailRequest{Token: "   "})
	if err == nil {
		t.Fatal("expected error on empty token, got nil")
	}
	st, ok = status.FromError(err)
	if !ok || st.Code() != codes.InvalidArgument {
		t.Fatalf("expected InvalidArgument on empty token, got %v", err)
	}
}

func TestServer_VerifyEmail_InternalErrorMasked(t *testing.T) {
	mockVS := &mockVerificationService{
		verifyEmailFunc: func(ctx context.Context, rawToken string) error {
			return errors.New("db connection pool exhausted")
		},
	}

	server := NewServer(nil, nil, WithVerificationService(mockVS))
	_, err := server.VerifyEmail(context.Background(), &authv1.VerifyEmailRequest{
		Token: "some_token",
	})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	st, ok := status.FromError(err)
	if !ok || st.Code() != codes.Internal {
		t.Fatalf("expected codes.Internal, got %v", err)
	}
	if st.Message() != "internal server error" {
		t.Fatalf("expected 'internal server error', got %q", st.Message())
	}
}

func TestServer_VerifyEmail_ServiceUnimplemented(t *testing.T) {
	server := NewServer(nil, nil) // no verification service configured
	_, err := server.VerifyEmail(context.Background(), &authv1.VerifyEmailRequest{
		Token: "some_token",
	})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	st, ok := status.FromError(err)
	if !ok || st.Code() != codes.Unimplemented {
		t.Fatalf("expected codes.Unimplemented, got %v", err)
	}
}
