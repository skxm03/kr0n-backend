package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	authv1 "github.com/skxm03/kr0n-backend/control-plane/gen/auth/v1"
)

type mockAuthClient struct {
	registerFunc func(ctx context.Context, in *authv1.RegisterRequest, opts ...grpc.CallOption) (*authv1.RegisterResponse, error)
	loginFunc    func(ctx context.Context, in *authv1.LoginRequest, opts ...grpc.CallOption) (*authv1.LoginResponse, error)
	refreshFunc  func(ctx context.Context, in *authv1.RefreshRequest, opts ...grpc.CallOption) (*authv1.RefreshResponse, error)
	logoutFunc   func(ctx context.Context, in *authv1.LogoutRequest, opts ...grpc.CallOption) (*authv1.LogoutResponse, error)
	verifyEmailFunc func(ctx context.Context, in *authv1.VerifyEmailRequest, opts ...grpc.CallOption) (*authv1.VerifyEmailResponse, error)
}

func (m *mockAuthClient) Register(ctx context.Context, in *authv1.RegisterRequest, opts ...grpc.CallOption) (*authv1.RegisterResponse, error) {
	if m.registerFunc != nil {
		return m.registerFunc(ctx, in, opts...)
	}
	return nil, nil
}

func (m *mockAuthClient) Login(ctx context.Context, in *authv1.LoginRequest, opts ...grpc.CallOption) (*authv1.LoginResponse, error) {
	if m.loginFunc != nil {
		return m.loginFunc(ctx, in, opts...)
	}
	return nil, nil
}

func (m *mockAuthClient) Refresh(ctx context.Context, in *authv1.RefreshRequest, opts ...grpc.CallOption) (*authv1.RefreshResponse, error) {
	if m.refreshFunc != nil {
		return m.refreshFunc(ctx, in, opts...)
	}
	return nil, nil
}

func (m *mockAuthClient) Logout(ctx context.Context, in *authv1.LogoutRequest, opts ...grpc.CallOption) (*authv1.LogoutResponse, error) {
	if m.logoutFunc != nil {
		return m.logoutFunc(ctx, in, opts...)
	}
	return nil, nil
}

func (m *mockAuthClient) VerifyEmail(ctx context.Context, in *authv1.VerifyEmailRequest, opts ...grpc.CallOption) (*authv1.VerifyEmailResponse, error) {
	if m.verifyEmailFunc != nil {
		return m.verifyEmailFunc(ctx, in, opts...)
	}
	return nil, nil
}

func TestHandler_Register_Success(t *testing.T) {
	createdAt := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	mockClient := &mockAuthClient{
		registerFunc: func(ctx context.Context, in *authv1.RegisterRequest, opts ...grpc.CallOption) (*authv1.RegisterResponse, error) {
			return &authv1.RegisterResponse{
				UserId:      "018f8e02-4b71-7000-8000-000000000001",
				Email:       in.GetEmail(),
				DisplayName: in.GetDisplayName(),
				Status:      "active",
				CreatedAt:   timestamppb.New(createdAt),
			}, nil
		},
	}

	h := NewHandler(mockClient)
	router := NewRouter(h)

	body := []byte(`{"email":"dev@kr0n.dev","password":"Password123!","display_name":"Developer"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected status 201 Created, got %d: body=%s", w.Code, w.Body.String())
	}

	var resp RegisterResponseDTO
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response failed: %v", err)
	}

	if resp.UserID != "018f8e02-4b71-7000-8000-000000000001" {
		t.Fatalf("unexpected user ID %s", resp.UserID)
	}
	if resp.Email != "dev@kr0n.dev" || resp.DisplayName != "Developer" || resp.Status != "active" {
		t.Fatalf("unexpected response payload: %+v", resp)
	}
}

func TestHandler_Register_MissingContentType(t *testing.T) {
	h := NewHandler(&mockAuthClient{})
	router := NewRouter(h)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/register", bytes.NewReader([]byte(`{}`)))
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("expected status 415, got %d", w.Code)
	}
}

func TestHandler_Register_MalformedJSON(t *testing.T) {
	h := NewHandler(&mockAuthClient{})
	router := NewRouter(h)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/register", bytes.NewReader([]byte(`{not valid json`)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", w.Code)
	}
}

func TestHandler_Register_MissingRequiredFields(t *testing.T) {
	h := NewHandler(&mockAuthClient{})
	router := NewRouter(h)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/register", bytes.NewReader([]byte(`{"email":"","password":"","display_name":""}`)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", w.Code)
	}
}

func TestHandler_Register_ConflictAlreadyExists(t *testing.T) {
	mockClient := &mockAuthClient{
		registerFunc: func(ctx context.Context, in *authv1.RegisterRequest, opts ...grpc.CallOption) (*authv1.RegisterResponse, error) {
			return nil, status.Error(codes.AlreadyExists, "email already registered")
		},
	}

	h := NewHandler(mockClient)
	router := NewRouter(h)

	body := []byte(`{"email":"dup@kr0n.dev","password":"Password123!","display_name":"Dup"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusConflict {
		t.Fatalf("expected status 409 Conflict, got %d", w.Code)
	}

	var errResp ErrorResponseDTO
	if err := json.Unmarshal(w.Body.Bytes(), &errResp); err != nil {
		t.Fatalf("unmarshal error response failed: %v", err)
	}
	if errResp.Code != "EMAIL_ALREADY_EXISTS" {
		t.Fatalf("expected code EMAIL_ALREADY_EXISTS, got %s", errResp.Code)
	}
}

func TestHandler_Register_InternalError(t *testing.T) {
	mockClient := &mockAuthClient{
		registerFunc: func(ctx context.Context, in *authv1.RegisterRequest, opts ...grpc.CallOption) (*authv1.RegisterResponse, error) {
			return nil, status.Error(codes.Internal, "internal server error")
		},
	}

	h := NewHandler(mockClient)
	router := NewRouter(h)

	body := []byte(`{"email":"err@kr0n.dev","password":"Password123!","display_name":"Err"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected status 500, got %d", w.Code)
	}
}

func TestHandler_Login_Success(t *testing.T) {
	mockClient := &mockAuthClient{
		loginFunc: func(ctx context.Context, in *authv1.LoginRequest, opts ...grpc.CallOption) (*authv1.LoginResponse, error) {
			return &authv1.LoginResponse{
				AccessToken:  "jwt.access.token",
				RefreshToken: "opaque.refresh.token",
				TokenType:    "Bearer",
				ExpiresIn:    900,
				User: &authv1.LoginUser{
					Id:          "018f8e02-4b71-7000-8000-000000000001",
					Email:       in.GetEmail(),
					DisplayName: "Developer",
					Status:      "active",
				},
			}, nil
		},
	}

	h := NewHandler(mockClient)
	router := NewRouter(h)

	body := []byte(`{"email":"dev@kr0n.dev","password":"Password123!"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200 OK, got %d: body=%s", w.Code, w.Body.String())
	}

	var resp LoginResponseDTO
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response failed: %v", err)
	}

	if resp.AccessToken != "jwt.access.token" {
		t.Fatalf("unexpected access token: %s", resp.AccessToken)
	}
	if resp.RefreshToken != "opaque.refresh.token" {
		t.Fatalf("unexpected refresh token: %s", resp.RefreshToken)
	}
	if resp.TokenType != "Bearer" {
		t.Fatalf("unexpected token type: %s", resp.TokenType)
	}
	if resp.ExpiresIn != 900 {
		t.Fatalf("unexpected expires_in: %d", resp.ExpiresIn)
	}
	if resp.User.Email != "dev@kr0n.dev" {
		t.Fatalf("unexpected user email: %s", resp.User.Email)
	}
}

func TestHandler_Login_InvalidCredentials(t *testing.T) {
	mockClient := &mockAuthClient{
		loginFunc: func(ctx context.Context, in *authv1.LoginRequest, opts ...grpc.CallOption) (*authv1.LoginResponse, error) {
			return nil, status.Error(codes.Unauthenticated, "invalid email or password")
		},
	}

	h := NewHandler(mockClient)
	router := NewRouter(h)

	body := []byte(`{"email":"dev@kr0n.dev","password":"WrongPassword"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected status 401 Unauthorized, got %d", w.Code)
	}

	var errResp ErrorResponseDTO
	if err := json.Unmarshal(w.Body.Bytes(), &errResp); err != nil {
		t.Fatalf("unmarshal error response failed: %v", err)
	}
	if errResp.Code != "UNAUTHORIZED" {
		t.Fatalf("expected code UNAUTHORIZED, got %s", errResp.Code)
	}
	if errResp.Error != "invalid email or password" {
		t.Fatalf("expected message 'invalid email or password', got %s", errResp.Error)
	}
}

func TestHandler_Login_MalformedJSON(t *testing.T) {
	h := NewHandler(&mockAuthClient{})
	router := NewRouter(h)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader([]byte(`{invalid`)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400 Bad Request, got %d", w.Code)
	}
}

func TestHandler_Login_MissingContentType(t *testing.T) {
	h := NewHandler(&mockAuthClient{})
	router := NewRouter(h)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader([]byte(`{}`)))
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("expected status 415, got %d", w.Code)
	}
}

func TestHandler_Login_InactiveUser(t *testing.T) {
	mockClient := &mockAuthClient{
		loginFunc: func(ctx context.Context, in *authv1.LoginRequest, opts ...grpc.CallOption) (*authv1.LoginResponse, error) {
			return nil, status.Error(codes.PermissionDenied, "user account is not active")
		},
	}

	h := NewHandler(mockClient)
	router := NewRouter(h)

	body := []byte(`{"email":"inactive@kr0n.dev","password":"Password123!"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected status 403 Forbidden, got %d", w.Code)
	}
}

func TestHandler_Refresh_Success(t *testing.T) {
	mockClient := &mockAuthClient{
		refreshFunc: func(ctx context.Context, in *authv1.RefreshRequest, opts ...grpc.CallOption) (*authv1.RefreshResponse, error) {
			return &authv1.RefreshResponse{
				AccessToken:  "new.jwt.access",
				RefreshToken: "new_opaque_refresh",
				TokenType:    "Bearer",
				ExpiresIn:    900,
			}, nil
		},
	}

	h := NewHandler(mockClient)
	router := NewRouter(h)

	body := []byte(`{"refresh_token":"valid_raw_refresh_token"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/refresh", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200 OK, got %d: body=%s", w.Code, w.Body.String())
	}

	var resp RefreshResponseDTO
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response failed: %v", err)
	}

	if resp.AccessToken != "new.jwt.access" {
		t.Fatalf("unexpected access token: %s", resp.AccessToken)
	}
	if resp.RefreshToken != "new_opaque_refresh" {
		t.Fatalf("unexpected refresh token: %s", resp.RefreshToken)
	}
	if resp.TokenType != "Bearer" {
		t.Fatalf("unexpected token type: %s", resp.TokenType)
	}
	if resp.ExpiresIn != 900 {
		t.Fatalf("expected 900 seconds, got %d", resp.ExpiresIn)
	}
}

func TestHandler_Refresh_InvalidToken(t *testing.T) {
	mockClient := &mockAuthClient{
		refreshFunc: func(ctx context.Context, in *authv1.RefreshRequest, opts ...grpc.CallOption) (*authv1.RefreshResponse, error) {
			return nil, status.Error(codes.Unauthenticated, "invalid refresh token")
		},
	}

	h := NewHandler(mockClient)
	router := NewRouter(h)

	body := []byte(`{"refresh_token":"invalid_token"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/refresh", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected status 401 Unauthorized, got %d", w.Code)
	}

	var errResp ErrorResponseDTO
	_ = json.Unmarshal(w.Body.Bytes(), &errResp)
	if errResp.Error != "invalid refresh token" {
		t.Fatalf("expected 'invalid refresh token', got %s", errResp.Error)
	}
	if errResp.Code != "UNAUTHORIZED" {
		t.Fatalf("expected code UNAUTHORIZED, got %s", errResp.Code)
	}
}

func TestHandler_Refresh_ExpiredOrRevokedToken(t *testing.T) {
	// gRPC maps expired/revoked to Unauthenticated "invalid refresh token"
	mockClient := &mockAuthClient{
		refreshFunc: func(ctx context.Context, in *authv1.RefreshRequest, opts ...grpc.CallOption) (*authv1.RefreshResponse, error) {
			return nil, status.Error(codes.Unauthenticated, "invalid refresh token")
		},
	}

	h := NewHandler(mockClient)
	router := NewRouter(h)

	body := []byte(`{"refresh_token":"revoked_or_expired_token"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/refresh", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected status 401 Unauthorized, got %d", w.Code)
	}

	var errResp ErrorResponseDTO
	_ = json.Unmarshal(w.Body.Bytes(), &errResp)
	if errResp.Error != "invalid refresh token" {
		t.Fatalf("expected 'invalid refresh token', got %s", errResp.Error)
	}
}

func TestHandler_Refresh_InactiveUser(t *testing.T) {
	mockClient := &mockAuthClient{
		refreshFunc: func(ctx context.Context, in *authv1.RefreshRequest, opts ...grpc.CallOption) (*authv1.RefreshResponse, error) {
			return nil, status.Error(codes.PermissionDenied, "user account is not active")
		},
	}

	h := NewHandler(mockClient)
	router := NewRouter(h)

	body := []byte(`{"refresh_token":"valid_token"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/refresh", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected status 403 Forbidden, got %d", w.Code)
	}

	var errResp ErrorResponseDTO
	_ = json.Unmarshal(w.Body.Bytes(), &errResp)
	if errResp.Code != "FORBIDDEN" {
		t.Fatalf("expected code FORBIDDEN, got %s", errResp.Code)
	}
}

func TestHandler_Refresh_MalformedJSON(t *testing.T) {
	h := NewHandler(&mockAuthClient{})
	router := NewRouter(h)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/refresh", bytes.NewReader([]byte(`{not valid`)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400 Bad Request, got %d", w.Code)
	}
}

func TestHandler_Refresh_MissingRefreshToken(t *testing.T) {
	h := NewHandler(&mockAuthClient{})
	router := NewRouter(h)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/refresh", bytes.NewReader([]byte(`{"refresh_token":""}`)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400 Bad Request, got %d", w.Code)
	}

	var errResp ErrorResponseDTO
	_ = json.Unmarshal(w.Body.Bytes(), &errResp)
	if errResp.Error != "refresh_token is required" {
		t.Fatalf("expected 'refresh_token is required', got %s", errResp.Error)
	}
}

func TestHandler_Refresh_WrongContentType(t *testing.T) {
	h := NewHandler(&mockAuthClient{})
	router := NewRouter(h)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/refresh", bytes.NewReader([]byte(`{}`)))
	req.Header.Set("Content-Type", "text/plain")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("expected status 415 Unsupported Media Type, got %d", w.Code)
	}
}

func TestHandler_Refresh_GRPCErrorMapping(t *testing.T) {
	testCases := []struct {
		name       string
		grpcErr    error
		wantStatus int
		wantCode   string
	}{
		{
			name:       "deadline exceeded",
			grpcErr:    status.Error(codes.DeadlineExceeded, "context deadline exceeded"),
			wantStatus: http.StatusGatewayTimeout,
			wantCode:   "GATEWAY_TIMEOUT",
		},
		{
			name:       "service unavailable",
			grpcErr:    status.Error(codes.Unavailable, "connection refused"),
			wantStatus: http.StatusServiceUnavailable,
			wantCode:   "SERVICE_UNAVAILABLE",
		},
		{
			name:       "internal error",
			grpcErr:    status.Error(codes.Internal, "panic in grpc handler"),
			wantStatus: http.StatusInternalServerError,
			wantCode:   "INTERNAL_ERROR",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockClient := &mockAuthClient{
				refreshFunc: func(ctx context.Context, in *authv1.RefreshRequest, opts ...grpc.CallOption) (*authv1.RefreshResponse, error) {
					return nil, tc.grpcErr
				},
			}
			h := NewHandler(mockClient)
			router := NewRouter(h)

			req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/refresh", bytes.NewReader([]byte(`{"refresh_token":"tok"}`)))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			if w.Code != tc.wantStatus {
				t.Fatalf("expected status %d, got %d", tc.wantStatus, w.Code)
			}
			var errResp ErrorResponseDTO
			_ = json.Unmarshal(w.Body.Bytes(), &errResp)
			if errResp.Code != tc.wantCode {
				t.Fatalf("expected code %s, got %s", tc.wantCode, errResp.Code)
			}
		})
	}
}

func TestHandler_Logout_Success(t *testing.T) {
	var loggedOutToken string
	mockClient := &mockAuthClient{
		logoutFunc: func(ctx context.Context, in *authv1.LogoutRequest, opts ...grpc.CallOption) (*authv1.LogoutResponse, error) {
			loggedOutToken = in.GetRefreshToken()
			return &authv1.LogoutResponse{}, nil
		},
	}

	h := NewHandler(mockClient)
	router := NewRouter(h)

	body := []byte(`{"refresh_token":"token_to_revoke"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/logout", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200 OK, got %d", w.Code)
	}

	var resp LogoutResponseDTO
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal logout response failed: %v", err)
	}
	if resp.Message != "logged out successfully" {
		t.Fatalf("expected message 'logged out successfully', got %s", resp.Message)
	}
	if loggedOutToken != "token_to_revoke" {
		t.Fatalf("expected logout called with token_to_revoke, got %s", loggedOutToken)
	}
}

func TestHandler_Logout_MalformedJSON(t *testing.T) {
	h := NewHandler(&mockAuthClient{})
	router := NewRouter(h)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/logout", bytes.NewReader([]byte(`{not valid json`)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400 Bad Request, got %d", w.Code)
	}
}

func TestHandler_Logout_MissingRefreshToken(t *testing.T) {
	h := NewHandler(&mockAuthClient{})
	router := NewRouter(h)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/logout", bytes.NewReader([]byte(`{"refresh_token":""}`)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400 Bad Request, got %d", w.Code)
	}

	var errResp ErrorResponseDTO
	_ = json.Unmarshal(w.Body.Bytes(), &errResp)
	if errResp.Error != "refresh_token is required" {
		t.Fatalf("expected 'refresh_token is required', got %s", errResp.Error)
	}
}

func TestHandler_Logout_WrongContentType(t *testing.T) {
	h := NewHandler(&mockAuthClient{})
	router := NewRouter(h)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/logout", bytes.NewReader([]byte(`{}`)))
	req.Header.Set("Content-Type", "text/plain")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("expected status 415 Unsupported Media Type, got %d", w.Code)
	}
}

func TestHandler_Logout_GRPCErrorMapping(t *testing.T) {
	testCases := []struct {
		name       string
		grpcErr    error
		wantStatus int
		wantCode   string
	}{
		{
			name:       "deadline exceeded",
			grpcErr:    status.Error(codes.DeadlineExceeded, "context deadline exceeded"),
			wantStatus: http.StatusGatewayTimeout,
			wantCode:   "GATEWAY_TIMEOUT",
		},
		{
			name:       "service unavailable",
			grpcErr:    status.Error(codes.Unavailable, "connection refused"),
			wantStatus: http.StatusServiceUnavailable,
			wantCode:   "SERVICE_UNAVAILABLE",
		},
		{
			name:       "internal error",
			grpcErr:    status.Error(codes.Internal, "panic in grpc handler"),
			wantStatus: http.StatusInternalServerError,
			wantCode:   "INTERNAL_ERROR",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockClient := &mockAuthClient{
				logoutFunc: func(ctx context.Context, in *authv1.LogoutRequest, opts ...grpc.CallOption) (*authv1.LogoutResponse, error) {
					return nil, tc.grpcErr
				},
			}
			h := NewHandler(mockClient)
			router := NewRouter(h)

			req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/logout", bytes.NewReader([]byte(`{"refresh_token":"tok"}`)))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			if w.Code != tc.wantStatus {
				t.Fatalf("expected status %d, got %d", tc.wantStatus, w.Code)
			}
			var errResp ErrorResponseDTO
			_ = json.Unmarshal(w.Body.Bytes(), &errResp)
			if errResp.Code != tc.wantCode {
				t.Fatalf("expected code %s, got %s", tc.wantCode, errResp.Code)
			}
		})
	}
}

func TestHandler_VerifyEmail_Success(t *testing.T) {
	mockClient := &mockAuthClient{
		verifyEmailFunc: func(ctx context.Context, in *authv1.VerifyEmailRequest, opts ...grpc.CallOption) (*authv1.VerifyEmailResponse, error) {
			if in.GetToken() != "valid_token_123" {
				return nil, status.Error(codes.InvalidArgument, "invalid or expired verification token")
			}
			return &authv1.VerifyEmailResponse{}, nil
		},
	}
	h := NewHandler(mockClient)
	router := NewRouter(h)

	bodyBytes, _ := json.Marshal(map[string]string{
		"token": "valid_token_123",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/verify-email", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200 OK, got %d (body: %s)", w.Code, w.Body.String())
	}

	var resp VerifyEmailResponseDTO
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp.Message != "email verified successfully" {
		t.Fatalf("expected message 'email verified successfully', got %q", resp.Message)
	}
}

func TestHandler_VerifyEmail_InvalidOrExpiredOrConsumedToken(t *testing.T) {
	testCases := []struct {
		name    string
		token   string
		grpcErr error
	}{
		{
			name:    "invalid token",
			token:   "invalid_tok",
			grpcErr: status.Error(codes.InvalidArgument, "invalid or expired verification token"),
		},
		{
			name:    "expired token",
			token:   "expired_tok",
			grpcErr: status.Error(codes.InvalidArgument, "invalid or expired verification token"),
		},
		{
			name:    "already consumed token",
			token:   "consumed_tok",
			grpcErr: status.Error(codes.InvalidArgument, "invalid or expired verification token"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockClient := &mockAuthClient{
				verifyEmailFunc: func(ctx context.Context, in *authv1.VerifyEmailRequest, opts ...grpc.CallOption) (*authv1.VerifyEmailResponse, error) {
					return nil, tc.grpcErr
				},
			}
			h := NewHandler(mockClient)
			router := NewRouter(h)

			bodyBytes, _ := json.Marshal(map[string]string{
				"token": tc.token,
			})
			req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/verify-email", bytes.NewReader(bodyBytes))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			if w.Code != http.StatusBadRequest {
				t.Fatalf("expected status 400 Bad Request, got %d", w.Code)
			}
			var errResp ErrorResponseDTO
			_ = json.Unmarshal(w.Body.Bytes(), &errResp)
			if errResp.Error != "invalid or expired verification token" {
				t.Fatalf("expected generic message 'invalid or expired verification token', got %q", errResp.Error)
			}
			if errResp.Code != "INVALID_ARGUMENT" {
				t.Fatalf("expected code INVALID_ARGUMENT, got %s", errResp.Code)
			}
		})
	}
}

func TestHandler_VerifyEmail_ValidationErrors(t *testing.T) {
	h := NewHandler(&mockAuthClient{})
	router := NewRouter(h)

	t.Run("wrong Content-Type", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/verify-email", bytes.NewReader([]byte(`{"token":"tok"}`)))
		req.Header.Set("Content-Type", "text/plain")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		if w.Code != http.StatusUnsupportedMediaType {
			t.Fatalf("expected 415 Unsupported Media Type, got %d", w.Code)
		}
	})

	t.Run("malformed JSON", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/verify-email", bytes.NewReader([]byte(`{not-json`)))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		if w.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 Bad Request, got %d", w.Code)
		}
		var errResp ErrorResponseDTO
		_ = json.Unmarshal(w.Body.Bytes(), &errResp)
		if errResp.Code != "MALFORMED_JSON" {
			t.Fatalf("expected MALFORMED_JSON code, got %s", errResp.Code)
		}
	})

	t.Run("missing token", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/verify-email", bytes.NewReader([]byte(`{"token":"  "}`)))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		if w.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 Bad Request, got %d", w.Code)
		}
		var errResp ErrorResponseDTO
		_ = json.Unmarshal(w.Body.Bytes(), &errResp)
		if errResp.Code != "INVALID_ARGUMENT" {
			t.Fatalf("expected INVALID_ARGUMENT code, got %s", errResp.Code)
		}
	})
}

func TestHandler_VerifyEmail_ErrorMapping(t *testing.T) {
	testCases := []struct {
		name       string
		grpcErr    error
		wantStatus int
		wantCode   string
	}{
		{
			name:       "deadline exceeded",
			grpcErr:    status.Error(codes.DeadlineExceeded, "deadline exceeded"),
			wantStatus: http.StatusGatewayTimeout,
			wantCode:   "GATEWAY_TIMEOUT",
		},
		{
			name:       "service unavailable",
			grpcErr:    status.Error(codes.Unavailable, "unavailable"),
			wantStatus: http.StatusServiceUnavailable,
			wantCode:   "SERVICE_UNAVAILABLE",
		},
		{
			name:       "internal error",
			grpcErr:    status.Error(codes.Internal, "panic in grpc"),
			wantStatus: http.StatusInternalServerError,
			wantCode:   "INTERNAL_ERROR",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockClient := &mockAuthClient{
				verifyEmailFunc: func(ctx context.Context, in *authv1.VerifyEmailRequest, opts ...grpc.CallOption) (*authv1.VerifyEmailResponse, error) {
					return nil, tc.grpcErr
				},
			}
			h := NewHandler(mockClient)
			router := NewRouter(h)

			bodyBytes, _ := json.Marshal(map[string]string{
				"token": "some_token",
			})
			req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/verify-email", bytes.NewReader(bodyBytes))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			if w.Code != tc.wantStatus {
				t.Fatalf("expected status %d, got %d", tc.wantStatus, w.Code)
			}
			var errResp ErrorResponseDTO
			_ = json.Unmarshal(w.Body.Bytes(), &errResp)
			if errResp.Code != tc.wantCode {
				t.Fatalf("expected code %s, got %s", tc.wantCode, errResp.Code)
			}
		})
	}
}
