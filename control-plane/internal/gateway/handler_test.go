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
	"github.com/skxm03/kr0n-backend/control-plane/internal/gateway/middleware"
)

type mockAuthClient struct {
	registerFunc             func(ctx context.Context, in *authv1.RegisterRequest, opts ...grpc.CallOption) (*authv1.RegisterResponse, error)
	loginFunc                func(ctx context.Context, in *authv1.LoginRequest, opts ...grpc.CallOption) (*authv1.LoginResponse, error)
	refreshFunc              func(ctx context.Context, in *authv1.RefreshRequest, opts ...grpc.CallOption) (*authv1.RefreshResponse, error)
	logoutFunc               func(ctx context.Context, in *authv1.LogoutRequest, opts ...grpc.CallOption) (*authv1.LogoutResponse, error)
	verifyEmailFunc          func(ctx context.Context, in *authv1.VerifyEmailRequest, opts ...grpc.CallOption) (*authv1.VerifyEmailResponse, error)
	getJWKSFunc              func(ctx context.Context, in *authv1.GetJWKSRequest, opts ...grpc.CallOption) (*authv1.GetJWKSResponse, error)
	resendVerificationFunc   func(ctx context.Context, in *authv1.ResendVerificationRequest, opts ...grpc.CallOption) (*authv1.ResendVerificationResponse, error)
	requestPasswordResetFunc func(ctx context.Context, in *authv1.RequestPasswordResetRequest, opts ...grpc.CallOption) (*authv1.RequestPasswordResetResponse, error)
	confirmPasswordResetFunc func(ctx context.Context, in *authv1.ConfirmPasswordResetRequest, opts ...grpc.CallOption) (*authv1.ConfirmPasswordResetResponse, error)
	changePasswordFunc       func(ctx context.Context, in *authv1.ChangePasswordRequest, opts ...grpc.CallOption) (*authv1.ChangePasswordResponse, error)
	getMeFunc                func(ctx context.Context, in *authv1.GetMeRequest, opts ...grpc.CallOption) (*authv1.GetMeResponse, error)
	listSessionsFunc         func(ctx context.Context, in *authv1.ListSessionsRequest, opts ...grpc.CallOption) (*authv1.ListSessionsResponse, error)
	revokeSessionFunc        func(ctx context.Context, in *authv1.RevokeSessionRequest, opts ...grpc.CallOption) (*authv1.RevokeSessionResponse, error)
	startGitHubOAuthFunc     func(ctx context.Context, in *authv1.StartGitHubOAuthRequest, opts ...grpc.CallOption) (*authv1.StartGitHubOAuthResponse, error)
	completeGitHubOAuthFunc  func(ctx context.Context, in *authv1.CompleteGitHubOAuthRequest, opts ...grpc.CallOption) (*authv1.CompleteGitHubOAuthResponse, error)
	checkPermissionFunc      func(ctx context.Context, in *authv1.CheckPermissionRequest, opts ...grpc.CallOption) (*authv1.CheckPermissionResponse, error)
	listRolesFunc            func(ctx context.Context, in *authv1.ListRolesRequest, opts ...grpc.CallOption) (*authv1.ListRolesResponse, error)
	createOrganizationFunc   func(ctx context.Context, in *authv1.CreateOrganizationRequest, opts ...grpc.CallOption) (*authv1.CreateOrganizationResponse, error)
	listOrganizationsFunc    func(ctx context.Context, in *authv1.ListOrganizationsRequest, opts ...grpc.CallOption) (*authv1.ListOrganizationsResponse, error)
	getOrganizationFunc      func(ctx context.Context, in *authv1.GetOrganizationRequest, opts ...grpc.CallOption) (*authv1.GetOrganizationResponse, error)
	updateOrganizationFunc   func(ctx context.Context, in *authv1.UpdateOrganizationRequest, opts ...grpc.CallOption) (*authv1.UpdateOrganizationResponse, error)
	deleteOrganizationFunc   func(ctx context.Context, in *authv1.DeleteOrganizationRequest, opts ...grpc.CallOption) (*authv1.DeleteOrganizationResponse, error)
	listMembersFunc          func(ctx context.Context, in *authv1.ListMembersRequest, opts ...grpc.CallOption) (*authv1.ListMembersResponse, error)
	addMemberFunc            func(ctx context.Context, in *authv1.AddMemberRequest, opts ...grpc.CallOption) (*authv1.AddMemberResponse, error)
	updateMemberRoleFunc     func(ctx context.Context, in *authv1.UpdateMemberRoleRequest, opts ...grpc.CallOption) (*authv1.UpdateMemberRoleResponse, error)
	removeMemberFunc         func(ctx context.Context, in *authv1.RemoveMemberRequest, opts ...grpc.CallOption) (*authv1.RemoveMemberResponse, error)
	createInviteFunc         func(ctx context.Context, in *authv1.CreateInviteRequest, opts ...grpc.CallOption) (*authv1.CreateInviteResponse, error)
	acceptInviteFunc         func(ctx context.Context, in *authv1.AcceptInviteRequest, opts ...grpc.CallOption) (*authv1.AcceptInviteResponse, error)
	revokeInviteFunc         func(ctx context.Context, in *authv1.RevokeInviteRequest, opts ...grpc.CallOption) (*authv1.RevokeInviteResponse, error)
	createAPITokenFunc       func(ctx context.Context, in *authv1.CreateAPITokenRequest, opts ...grpc.CallOption) (*authv1.CreateAPITokenResponse, error)
	listAPITokensFunc        func(ctx context.Context, in *authv1.ListAPITokensRequest, opts ...grpc.CallOption) (*authv1.ListAPITokensResponse, error)
	revokeAPITokenFunc       func(ctx context.Context, in *authv1.RevokeAPITokenRequest, opts ...grpc.CallOption) (*authv1.RevokeAPITokenResponse, error)
	validateAPITokenFunc     func(ctx context.Context, in *authv1.ValidateAPITokenRequest, opts ...grpc.CallOption) (*authv1.ValidateAPITokenResponse, error)
	listAuditEventsFunc      func(ctx context.Context, in *authv1.ListAuditEventsRequest, opts ...grpc.CallOption) (*authv1.ListAuditEventsResponse, error)
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

func (m *mockAuthClient) GetJWKS(ctx context.Context, in *authv1.GetJWKSRequest, opts ...grpc.CallOption) (*authv1.GetJWKSResponse, error) {
	if m.getJWKSFunc != nil {
		return m.getJWKSFunc(ctx, in, opts...)
	}
	return &authv1.GetJWKSResponse{}, nil
}

func (m *mockAuthClient) ResendVerification(ctx context.Context, in *authv1.ResendVerificationRequest, opts ...grpc.CallOption) (*authv1.ResendVerificationResponse, error) {
	if m.resendVerificationFunc != nil {
		return m.resendVerificationFunc(ctx, in, opts...)
	}
	return &authv1.ResendVerificationResponse{}, nil
}

func (m *mockAuthClient) RequestPasswordReset(ctx context.Context, in *authv1.RequestPasswordResetRequest, opts ...grpc.CallOption) (*authv1.RequestPasswordResetResponse, error) {
	if m.requestPasswordResetFunc != nil {
		return m.requestPasswordResetFunc(ctx, in, opts...)
	}
	return &authv1.RequestPasswordResetResponse{}, nil
}

func (m *mockAuthClient) ConfirmPasswordReset(ctx context.Context, in *authv1.ConfirmPasswordResetRequest, opts ...grpc.CallOption) (*authv1.ConfirmPasswordResetResponse, error) {
	if m.confirmPasswordResetFunc != nil {
		return m.confirmPasswordResetFunc(ctx, in, opts...)
	}
	return &authv1.ConfirmPasswordResetResponse{}, nil
}

func (m *mockAuthClient) ChangePassword(ctx context.Context, in *authv1.ChangePasswordRequest, opts ...grpc.CallOption) (*authv1.ChangePasswordResponse, error) {
	if m.changePasswordFunc != nil {
		return m.changePasswordFunc(ctx, in, opts...)
	}
	return &authv1.ChangePasswordResponse{}, nil
}

func (m *mockAuthClient) GetMe(ctx context.Context, in *authv1.GetMeRequest, opts ...grpc.CallOption) (*authv1.GetMeResponse, error) {
	if m.getMeFunc != nil {
		return m.getMeFunc(ctx, in, opts...)
	}
	return nil, nil
}

func (m *mockAuthClient) ListSessions(ctx context.Context, in *authv1.ListSessionsRequest, opts ...grpc.CallOption) (*authv1.ListSessionsResponse, error) {
	if m.listSessionsFunc != nil {
		return m.listSessionsFunc(ctx, in, opts...)
	}
	return &authv1.ListSessionsResponse{}, nil
}

func (m *mockAuthClient) RevokeSession(ctx context.Context, in *authv1.RevokeSessionRequest, opts ...grpc.CallOption) (*authv1.RevokeSessionResponse, error) {
	if m.revokeSessionFunc != nil {
		return m.revokeSessionFunc(ctx, in, opts...)
	}
	return &authv1.RevokeSessionResponse{}, nil
}

func (m *mockAuthClient) StartGitHubOAuth(ctx context.Context, in *authv1.StartGitHubOAuthRequest, opts ...grpc.CallOption) (*authv1.StartGitHubOAuthResponse, error) {
	if m.startGitHubOAuthFunc != nil {
		return m.startGitHubOAuthFunc(ctx, in, opts...)
	}
	return nil, status.Error(codes.FailedPrecondition, "github oauth is not configured")
}

func (m *mockAuthClient) CompleteGitHubOAuth(ctx context.Context, in *authv1.CompleteGitHubOAuthRequest, opts ...grpc.CallOption) (*authv1.CompleteGitHubOAuthResponse, error) {
	if m.completeGitHubOAuthFunc != nil {
		return m.completeGitHubOAuthFunc(ctx, in, opts...)
	}
	return nil, status.Error(codes.FailedPrecondition, "github oauth is not configured")
}

func (m *mockAuthClient) CheckPermission(ctx context.Context, in *authv1.CheckPermissionRequest, opts ...grpc.CallOption) (*authv1.CheckPermissionResponse, error) {
	if m.checkPermissionFunc != nil {
		return m.checkPermissionFunc(ctx, in, opts...)
	}
	return &authv1.CheckPermissionResponse{Allowed: true}, nil
}

func (m *mockAuthClient) ListRoles(ctx context.Context, in *authv1.ListRolesRequest, opts ...grpc.CallOption) (*authv1.ListRolesResponse, error) {
	if m.listRolesFunc != nil {
		return m.listRolesFunc(ctx, in, opts...)
	}
	return &authv1.ListRolesResponse{}, nil
}

func (m *mockAuthClient) CreateOrganization(ctx context.Context, in *authv1.CreateOrganizationRequest, opts ...grpc.CallOption) (*authv1.CreateOrganizationResponse, error) {
	if m.createOrganizationFunc != nil {
		return m.createOrganizationFunc(ctx, in, opts...)
	}
	return &authv1.CreateOrganizationResponse{}, nil
}

func (m *mockAuthClient) ListOrganizations(ctx context.Context, in *authv1.ListOrganizationsRequest, opts ...grpc.CallOption) (*authv1.ListOrganizationsResponse, error) {
	if m.listOrganizationsFunc != nil {
		return m.listOrganizationsFunc(ctx, in, opts...)
	}
	return &authv1.ListOrganizationsResponse{}, nil
}

func (m *mockAuthClient) GetOrganization(ctx context.Context, in *authv1.GetOrganizationRequest, opts ...grpc.CallOption) (*authv1.GetOrganizationResponse, error) {
	if m.getOrganizationFunc != nil {
		return m.getOrganizationFunc(ctx, in, opts...)
	}
	return &authv1.GetOrganizationResponse{}, nil
}

func (m *mockAuthClient) UpdateOrganization(ctx context.Context, in *authv1.UpdateOrganizationRequest, opts ...grpc.CallOption) (*authv1.UpdateOrganizationResponse, error) {
	if m.updateOrganizationFunc != nil {
		return m.updateOrganizationFunc(ctx, in, opts...)
	}
	return &authv1.UpdateOrganizationResponse{}, nil
}

func (m *mockAuthClient) DeleteOrganization(ctx context.Context, in *authv1.DeleteOrganizationRequest, opts ...grpc.CallOption) (*authv1.DeleteOrganizationResponse, error) {
	if m.deleteOrganizationFunc != nil {
		return m.deleteOrganizationFunc(ctx, in, opts...)
	}
	return &authv1.DeleteOrganizationResponse{}, nil
}

func (m *mockAuthClient) ListMembers(ctx context.Context, in *authv1.ListMembersRequest, opts ...grpc.CallOption) (*authv1.ListMembersResponse, error) {
	if m.listMembersFunc != nil {
		return m.listMembersFunc(ctx, in, opts...)
	}
	return &authv1.ListMembersResponse{}, nil
}

func (m *mockAuthClient) AddMember(ctx context.Context, in *authv1.AddMemberRequest, opts ...grpc.CallOption) (*authv1.AddMemberResponse, error) {
	if m.addMemberFunc != nil {
		return m.addMemberFunc(ctx, in, opts...)
	}
	return &authv1.AddMemberResponse{}, nil
}

func (m *mockAuthClient) UpdateMemberRole(ctx context.Context, in *authv1.UpdateMemberRoleRequest, opts ...grpc.CallOption) (*authv1.UpdateMemberRoleResponse, error) {
	if m.updateMemberRoleFunc != nil {
		return m.updateMemberRoleFunc(ctx, in, opts...)
	}
	return &authv1.UpdateMemberRoleResponse{}, nil
}

func (m *mockAuthClient) RemoveMember(ctx context.Context, in *authv1.RemoveMemberRequest, opts ...grpc.CallOption) (*authv1.RemoveMemberResponse, error) {
	if m.removeMemberFunc != nil {
		return m.removeMemberFunc(ctx, in, opts...)
	}
	return &authv1.RemoveMemberResponse{}, nil
}

func (m *mockAuthClient) CreateInvite(ctx context.Context, in *authv1.CreateInviteRequest, opts ...grpc.CallOption) (*authv1.CreateInviteResponse, error) {
	if m.createInviteFunc != nil {
		return m.createInviteFunc(ctx, in, opts...)
	}
	return &authv1.CreateInviteResponse{}, nil
}

func (m *mockAuthClient) AcceptInvite(ctx context.Context, in *authv1.AcceptInviteRequest, opts ...grpc.CallOption) (*authv1.AcceptInviteResponse, error) {
	if m.acceptInviteFunc != nil {
		return m.acceptInviteFunc(ctx, in, opts...)
	}
	return &authv1.AcceptInviteResponse{}, nil
}

func (m *mockAuthClient) RevokeInvite(ctx context.Context, in *authv1.RevokeInviteRequest, opts ...grpc.CallOption) (*authv1.RevokeInviteResponse, error) {
	if m.revokeInviteFunc != nil {
		return m.revokeInviteFunc(ctx, in, opts...)
	}
	return &authv1.RevokeInviteResponse{}, nil
}

func (m *mockAuthClient) CreateAPIToken(ctx context.Context, in *authv1.CreateAPITokenRequest, opts ...grpc.CallOption) (*authv1.CreateAPITokenResponse, error) {
	if m.createAPITokenFunc != nil {
		return m.createAPITokenFunc(ctx, in, opts...)
	}
	return &authv1.CreateAPITokenResponse{}, nil
}

func (m *mockAuthClient) ListAPITokens(ctx context.Context, in *authv1.ListAPITokensRequest, opts ...grpc.CallOption) (*authv1.ListAPITokensResponse, error) {
	if m.listAPITokensFunc != nil {
		return m.listAPITokensFunc(ctx, in, opts...)
	}
	return &authv1.ListAPITokensResponse{}, nil
}

func (m *mockAuthClient) RevokeAPIToken(ctx context.Context, in *authv1.RevokeAPITokenRequest, opts ...grpc.CallOption) (*authv1.RevokeAPITokenResponse, error) {
	if m.revokeAPITokenFunc != nil {
		return m.revokeAPITokenFunc(ctx, in, opts...)
	}
	return &authv1.RevokeAPITokenResponse{}, nil
}

func (m *mockAuthClient) ValidateAPIToken(ctx context.Context, in *authv1.ValidateAPITokenRequest, opts ...grpc.CallOption) (*authv1.ValidateAPITokenResponse, error) {
	if m.validateAPITokenFunc != nil {
		return m.validateAPITokenFunc(ctx, in, opts...)
	}
	return nil, status.Error(codes.Unauthenticated, "invalid api token")
}

func (m *mockAuthClient) ListAuditEvents(ctx context.Context, in *authv1.ListAuditEventsRequest, opts ...grpc.CallOption) (*authv1.ListAuditEventsResponse, error) {
	if m.listAuditEventsFunc != nil {
		return m.listAuditEventsFunc(ctx, in, opts...)
	}
	return &authv1.ListAuditEventsResponse{}, nil
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
	router := NewServerHandler(h, Options{})

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
	router := NewServerHandler(h, Options{})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/register", bytes.NewReader([]byte(`{}`)))
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("expected status 415, got %d", w.Code)
	}
}

func TestHandler_Register_MalformedJSON(t *testing.T) {
	h := NewHandler(&mockAuthClient{})
	router := NewServerHandler(h, Options{})

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
	router := NewServerHandler(h, Options{})

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
	router := NewServerHandler(h, Options{})

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
	router := NewServerHandler(h, Options{})

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
	router := NewServerHandler(h, Options{})

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
	router := NewServerHandler(h, Options{})

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
	router := NewServerHandler(h, Options{})

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
	router := NewServerHandler(h, Options{})

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
	router := NewServerHandler(h, Options{})

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
	router := NewServerHandler(h, Options{})

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
	router := NewServerHandler(h, Options{})

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
	router := NewServerHandler(h, Options{})

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
	router := NewServerHandler(h, Options{})

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
	router := NewServerHandler(h, Options{})

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
	router := NewServerHandler(h, Options{})

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
	router := NewServerHandler(h, Options{})

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
			router := NewServerHandler(h, Options{})

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
	router := NewServerHandler(h, Options{})

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
	router := NewServerHandler(h, Options{})

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
	router := NewServerHandler(h, Options{})

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
	router := NewServerHandler(h, Options{})

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
			router := NewServerHandler(h, Options{})

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
	router := NewServerHandler(h, Options{})

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
			router := NewServerHandler(h, Options{})

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
	router := NewServerHandler(h, Options{})

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
			router := NewServerHandler(h, Options{})

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

func TestHandler_P4Endpoints(t *testing.T) {
	now := time.Now().UTC()
	mockClient := &mockAuthClient{
		getMeFunc: func(ctx context.Context, in *authv1.GetMeRequest, opts ...grpc.CallOption) (*authv1.GetMeResponse, error) {
			return &authv1.GetMeResponse{
				Id:              in.GetUserId(),
				Email:           "me@kr0n.dev",
				DisplayName:     "Me",
				Status:          "active",
				EmailVerified:   true,
				EmailVerifiedAt: timestamppb.New(now),
				CreatedAt:       timestamppb.New(now),
			}, nil
		},
		listSessionsFunc: func(ctx context.Context, in *authv1.ListSessionsRequest, opts ...grpc.CallOption) (*authv1.ListSessionsResponse, error) {
			return &authv1.ListSessionsResponse{
				Sessions: []*authv1.SessionInfo{
					{
						Id:         "s1",
						UserAgent:  "UA",
						IpAddress:  "127.0.0.1",
						CreatedAt:  timestamppb.New(now),
						LastSeenAt: timestamppb.New(now),
						ExpiresAt:  timestamppb.New(now.Add(time.Hour)),
					},
				},
			}, nil
		},
	}

	h := NewHandler(mockClient)
	router := NewServerHandler(h, Options{})

	// 1. POST /api/v1/auth/resend-verification
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/resend-verification", bytes.NewReader([]byte(`{"email":"me@kr0n.dev"}`)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("resend-verification: got %d (%s)", w.Code, w.Body.String())
	}

	// 2. POST /api/v1/auth/password-reset/request
	req = httptest.NewRequest(http.MethodPost, "/api/v1/auth/password-reset/request", bytes.NewReader([]byte(`{"email":"me@kr0n.dev"}`)))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("password-reset/request: got %d (%s)", w.Code, w.Body.String())
	}

	// 3. POST /api/v1/auth/password-reset/confirm
	req = httptest.NewRequest(http.MethodPost, "/api/v1/auth/password-reset/confirm", bytes.NewReader([]byte(`{"token":"tok","new_password":"NewValidPassword123!"}`)))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("password-reset/confirm: got %d (%s)", w.Code, w.Body.String())
	}

	// Helper to attach Principal to request
	withPrincipal := func(r *http.Request) *http.Request {
		return r.WithContext(middleware.WithPrincipal(r.Context(), &middleware.Principal{
			UserID:    "u1",
			SessionID: "s1",
			Kind:      "session",
		}))
	}

	// 4. POST /api/v1/auth/password/change
	req = withPrincipal(httptest.NewRequest(http.MethodPost, "/api/v1/auth/password/change", bytes.NewReader([]byte(`{"current_password":"old","new_password":"NewValidPassword123!"}`))))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("password/change: got %d (%s)", w.Code, w.Body.String())
	}

	// 5. GET /api/v1/me
	req = withPrincipal(httptest.NewRequest(http.MethodGet, "/api/v1/me", nil))
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("GET /api/v1/me: got %d (%s)", w.Code, w.Body.String())
	}
	var me MeResponseDTO
	if err := json.Unmarshal(w.Body.Bytes(), &me); err != nil || me.Email != "me@kr0n.dev" || !me.EmailVerified {
		t.Fatalf("unexpected me response: %v %+v", err, me)
	}

	// 6. GET /api/v1/auth/sessions
	req = withPrincipal(httptest.NewRequest(http.MethodGet, "/api/v1/auth/sessions", nil))
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("GET /api/v1/auth/sessions: got %d (%s)", w.Code, w.Body.String())
	}
	var listResp ListSessionsResponseDTO
	if err := json.Unmarshal(w.Body.Bytes(), &listResp); err != nil || len(listResp.Sessions) != 1 || !listResp.Sessions[0].Current {
		t.Fatalf("unexpected sessions response: %v %+v", err, listResp)
	}

	// 7. DELETE /api/v1/auth/sessions/{id}
	req = withPrincipal(httptest.NewRequest(http.MethodDelete, "/api/v1/auth/sessions/s1", nil))
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("DELETE /api/v1/auth/sessions/s1: got %d (%s)", w.Code, w.Body.String())
	}
}

func TestHandler_GitHubOAuth(t *testing.T) {
	// 1. When unset -> 503 not_configured
	unsetRouter := NewServerHandler(NewHandler(&mockAuthClient{}), Options{})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/github/start", nil)
	w := httptest.NewRecorder()
	unsetRouter.ServeHTTP(w, req)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 when not configured, got %d (%s)", w.Code, w.Body.String())
	}
	var errDTO ErrorResponseDTO
	_ = json.Unmarshal(w.Body.Bytes(), &errDTO)
	if errDTO.Code != "not_configured" {
		t.Fatalf("expected code not_configured, got %q", errDTO.Code)
	}

	// 2. Configured flow: /start sets HttpOnly cookie + 302 redirect, /callback validates state and returns tokens
	mockClient := &mockAuthClient{
		startGitHubOAuthFunc: func(ctx context.Context, in *authv1.StartGitHubOAuthRequest, opts ...grpc.CallOption) (*authv1.StartGitHubOAuthResponse, error) {
			return &authv1.StartGitHubOAuthResponse{
				AuthorizeUrl: "https://github.com/login/oauth/authorize?state=st123",
				State:        "st123",
				CodeVerifier: "ver456",
			}, nil
		},
		completeGitHubOAuthFunc: func(ctx context.Context, in *authv1.CompleteGitHubOAuthRequest, opts ...grpc.CallOption) (*authv1.CompleteGitHubOAuthResponse, error) {
			if in.GetCode() != "gh_code" || in.GetCodeVerifier() != "ver456" {
				return nil, status.Error(codes.Unauthenticated, "bad code or verifier")
			}
			return &authv1.CompleteGitHubOAuthResponse{
				AccessToken:  "jwt_tok",
				RefreshToken: "ref_tok",
				TokenType:    "Bearer",
				ExpiresIn:    900,
				User: &authv1.LoginUser{
					Id:          "u_gh",
					Email:       "octo@kr0n.dev",
					DisplayName: "Octo",
					Status:      "active",
				},
			}, nil
		},
	}
	router := NewServerHandler(NewHandler(mockClient), Options{})

	startReq := httptest.NewRequest(http.MethodGet, "/api/v1/auth/github/start", nil)
	startW := httptest.NewRecorder()
	router.ServeHTTP(startW, startReq)
	if startW.Code != http.StatusFound || startW.Header().Get("Location") != "https://github.com/login/oauth/authorize?state=st123" {
		t.Fatalf("unexpected start response: %d loc=%q", startW.Code, startW.Header().Get("Location"))
	}
	var oauthCookie *http.Cookie
	for _, c := range startW.Result().Cookies() {
		if c.Name == githubOAuthCookieName {
			oauthCookie = c
		}
	}
	if oauthCookie == nil || !oauthCookie.HttpOnly {
		t.Fatalf("expected HttpOnly %s cookie, got %+v", githubOAuthCookieName, oauthCookie)
	}

	// State mismatch -> 400
	badCb := httptest.NewRequest(http.MethodGet, "/api/v1/auth/github/callback?code=gh_code&state=wrong", nil)
	badCb.AddCookie(oauthCookie)
	badW := httptest.NewRecorder()
	router.ServeHTTP(badW, badCb)
	if badW.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 on state mismatch, got %d", badW.Code)
	}

	// Valid state + code -> 200 LoginResponseDTO
	cbReq := httptest.NewRequest(http.MethodGet, "/api/v1/auth/github/callback?code=gh_code&state=st123", nil)
	cbReq.AddCookie(oauthCookie)
	cbW := httptest.NewRecorder()
	router.ServeHTTP(cbW, cbReq)
	if cbW.Code != http.StatusOK {
		t.Fatalf("expected 200 on callback, got %d (%s)", cbW.Code, cbW.Body.String())
	}
	var loginResp LoginResponseDTO
	if err := json.Unmarshal(cbW.Body.Bytes(), &loginResp); err != nil || loginResp.AccessToken != "jwt_tok" || loginResp.User.Email != "octo@kr0n.dev" {
		t.Fatalf("unexpected callback body: %v %+v", err, loginResp)
	}
}

func TestHandler_P6_OrgsMembersInvitesAPITokens(t *testing.T) {
	now := timestamppb.New(time.Now().UTC().Truncate(time.Second))
	mockClient := &mockAuthClient{
		listRolesFunc: func(ctx context.Context, in *authv1.ListRolesRequest, opts ...grpc.CallOption) (*authv1.ListRolesResponse, error) {
			return &authv1.ListRolesResponse{
				Roles: []*authv1.RoleInfo{{Id: "owner", Name: "Owner", Permissions: []string{"org:read", "org:delete"}}},
			}, nil
		},
		createOrganizationFunc: func(ctx context.Context, in *authv1.CreateOrganizationRequest, opts ...grpc.CallOption) (*authv1.CreateOrganizationResponse, error) {
			return &authv1.CreateOrganizationResponse{
				Id: "org-1", Name: in.GetName(), Slug: in.GetSlug(), RoleId: "owner", CreatedAt: now, UpdatedAt: now,
			}, nil
		},
		listOrganizationsFunc: func(ctx context.Context, in *authv1.ListOrganizationsRequest, opts ...grpc.CallOption) (*authv1.ListOrganizationsResponse, error) {
			return &authv1.ListOrganizationsResponse{
				Organizations: []*authv1.OrganizationResponse{
					{Id: "org-1", Name: "Acme", Slug: "acme", RoleId: "owner", CreatedAt: now, UpdatedAt: now},
				},
			}, nil
		},
		getOrganizationFunc: func(ctx context.Context, in *authv1.GetOrganizationRequest, opts ...grpc.CallOption) (*authv1.GetOrganizationResponse, error) {
			return &authv1.GetOrganizationResponse{
				Id: in.GetOrgId(), Name: "Acme", Slug: "acme", RoleId: "owner", CreatedAt: now, UpdatedAt: now,
			}, nil
		},
		updateOrganizationFunc: func(ctx context.Context, in *authv1.UpdateOrganizationRequest, opts ...grpc.CallOption) (*authv1.UpdateOrganizationResponse, error) {
			return &authv1.UpdateOrganizationResponse{
				Id: in.GetOrgId(), Name: in.GetName(), Slug: "acme", RoleId: "owner", CreatedAt: now, UpdatedAt: now,
			}, nil
		},
		listMembersFunc: func(ctx context.Context, in *authv1.ListMembersRequest, opts ...grpc.CallOption) (*authv1.ListMembersResponse, error) {
			return &authv1.ListMembersResponse{
				Members: []*authv1.MemberInfo{{UserId: "u1", Email: "owner@kr0n.dev", DisplayName: "Owner", RoleId: "owner", CreatedAt: now}},
			}, nil
		},
		addMemberFunc: func(ctx context.Context, in *authv1.AddMemberRequest, opts ...grpc.CallOption) (*authv1.AddMemberResponse, error) {
			return &authv1.AddMemberResponse{UserId: "u2", Email: in.GetEmail(), DisplayName: "Dev", RoleId: in.GetRoleId(), CreatedAt: now}, nil
		},
		removeMemberFunc: func(ctx context.Context, in *authv1.RemoveMemberRequest, opts ...grpc.CallOption) (*authv1.RemoveMemberResponse, error) {
			if in.GetTargetUserId() == "u1" {
				return nil, status.Error(codes.FailedPrecondition, "cannot remove or demote the last owner of an organization")
			}
			return &authv1.RemoveMemberResponse{}, nil
		},
		createInviteFunc: func(ctx context.Context, in *authv1.CreateInviteRequest, opts ...grpc.CallOption) (*authv1.CreateInviteResponse, error) {
			return &authv1.CreateInviteResponse{
				Id: "inv-1", OrgId: in.GetOrgId(), Email: in.GetEmail(), RoleId: in.GetRoleId(), Token: "raw_inv_tok", ExpiresAt: now, CreatedAt: now,
			}, nil
		},
		acceptInviteFunc: func(ctx context.Context, in *authv1.AcceptInviteRequest, opts ...grpc.CallOption) (*authv1.AcceptInviteResponse, error) {
			return &authv1.AcceptInviteResponse{Id: "org-1", Name: "Acme", Slug: "acme", RoleId: "developer", CreatedAt: now, UpdatedAt: now}, nil
		},
		createAPITokenFunc: func(ctx context.Context, in *authv1.CreateAPITokenRequest, opts ...grpc.CallOption) (*authv1.CreateAPITokenResponse, error) {
			return &authv1.CreateAPITokenResponse{
				Token: &authv1.APITokenInfo{
					Id: "tok-1", OrgId: in.GetOrgId(), CreatedByUserId: in.GetCaller().GetUserId(),
					Name: in.GetName(), TokenPrefix: "kr0n_pat_abcdef01", Permissions: in.GetPermissions(), CreatedAt: now,
				},
				Secret: "kr0n_pat_abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
			}, nil
		},
		listAPITokensFunc: func(ctx context.Context, in *authv1.ListAPITokensRequest, opts ...grpc.CallOption) (*authv1.ListAPITokensResponse, error) {
			return &authv1.ListAPITokensResponse{
				Tokens: []*authv1.APITokenInfo{{
					Id: "tok-1", OrgId: in.GetOrgId(), CreatedByUserId: "u1", Name: "ci", TokenPrefix: "kr0n_pat_abcdef01", Permissions: []string{"org:read"}, CreatedAt: now,
				}},
			}, nil
		},
	}

	router := NewServerHandler(NewHandler(mockClient), Options{})
	withUser := func(r *http.Request) *http.Request {
		return r.WithContext(middleware.WithPrincipal(r.Context(), &middleware.Principal{
			UserID: "u1", SessionID: "s1", Kind: middleware.PrincipalKindSession,
		}))
	}

	// 1. GET /api/v1/roles
	w := httptest.NewRecorder()
	router.ServeHTTP(w, withUser(httptest.NewRequest(http.MethodGet, "/api/v1/roles", nil)))
	if w.Code != http.StatusOK || !bytes.Contains(w.Body.Bytes(), []byte(`"owner"`)) {
		t.Fatalf("GET /api/v1/roles: %d %s", w.Code, w.Body.String())
	}

	// 2. POST /api/v1/orgs
	req := withUser(httptest.NewRequest(http.MethodPost, "/api/v1/orgs", bytes.NewReader([]byte(`{"name":"Acme","slug":"acme"}`))))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("POST /api/v1/orgs: %d %s", w.Code, w.Body.String())
	}

	// 3. GET /api/v1/orgs and GET /api/v1/orgs/{id}
	w = httptest.NewRecorder()
	router.ServeHTTP(w, withUser(httptest.NewRequest(http.MethodGet, "/api/v1/orgs", nil)))
	if w.Code != http.StatusOK {
		t.Fatalf("GET /api/v1/orgs: %d", w.Code)
	}
	w = httptest.NewRecorder()
	router.ServeHTTP(w, withUser(httptest.NewRequest(http.MethodGet, "/api/v1/orgs/org-1", nil)))
	if w.Code != http.StatusOK {
		t.Fatalf("GET /api/v1/orgs/org-1: %d", w.Code)
	}

	// 4. PATCH /api/v1/orgs/{id} and DELETE /api/v1/orgs/{id}
	req = withUser(httptest.NewRequest(http.MethodPatch, "/api/v1/orgs/org-1", bytes.NewReader([]byte(`{"name":"Acme Renamed"}`))))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("PATCH /api/v1/orgs/org-1: %d", w.Code)
	}
	w = httptest.NewRecorder()
	router.ServeHTTP(w, withUser(httptest.NewRequest(http.MethodDelete, "/api/v1/orgs/org-1", nil)))
	if w.Code != http.StatusOK {
		t.Fatalf("DELETE /api/v1/orgs/org-1: %d", w.Code)
	}

	// 5. Members + Last-Owner guard (409 Conflict)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, withUser(httptest.NewRequest(http.MethodGet, "/api/v1/orgs/org-1/members", nil)))
	if w.Code != http.StatusOK {
		t.Fatalf("GET members: %d", w.Code)
	}
	req = withUser(httptest.NewRequest(http.MethodPost, "/api/v1/orgs/org-1/members", bytes.NewReader([]byte(`{"email":"dev@kr0n.dev","role_id":"developer"}`))))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("POST members: %d %s", w.Code, w.Body.String())
	}
	req = withUser(httptest.NewRequest(http.MethodPatch, "/api/v1/orgs/org-1/members/u2", bytes.NewReader([]byte(`{"role_id":"admin"}`))))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("PATCH member role: %d", w.Code)
	}
	w = httptest.NewRecorder()
	router.ServeHTTP(w, withUser(httptest.NewRequest(http.MethodDelete, "/api/v1/orgs/org-1/members/u1", nil)))
	if w.Code != http.StatusConflict {
		t.Fatalf("expected 409 Conflict when removing last owner, got %d (%s)", w.Code, w.Body.String())
	}

	// 6. Invites (create, accept, revoke)
	req = withUser(httptest.NewRequest(http.MethodPost, "/api/v1/orgs/org-1/invites", bytes.NewReader([]byte(`{"email":"new@kr0n.dev","role_id":"developer"}`))))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("POST invites: %d %s", w.Code, w.Body.String())
	}
	req = withUser(httptest.NewRequest(http.MethodPost, "/api/v1/orgs/invites/accept", bytes.NewReader([]byte(`{"token":"raw_inv_tok"}`))))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("POST invites/accept: %d %s", w.Code, w.Body.String())
	}
	w = httptest.NewRecorder()
	router.ServeHTTP(w, withUser(httptest.NewRequest(http.MethodDelete, "/api/v1/orgs/org-1/invites/inv-1", nil)))
	if w.Code != http.StatusOK {
		t.Fatalf("DELETE invite: %d", w.Code)
	}

	// 7. API Tokens (create, list, revoke)
	req = withUser(httptest.NewRequest(http.MethodPost, "/api/v1/orgs/org-1/tokens", bytes.NewReader([]byte(`{"name":"ci","permissions":["org:read"]}`))))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusCreated || !bytes.Contains(w.Body.Bytes(), []byte(`"kr0n_pat_abcdef01`)) {
		t.Fatalf("POST tokens: %d %s", w.Code, w.Body.String())
	}
	w = httptest.NewRecorder()
	router.ServeHTTP(w, withUser(httptest.NewRequest(http.MethodGet, "/api/v1/orgs/org-1/tokens", nil)))
	if w.Code != http.StatusOK {
		t.Fatalf("GET tokens: %d", w.Code)
	}
	w = httptest.NewRecorder()
	router.ServeHTTP(w, withUser(httptest.NewRequest(http.MethodDelete, "/api/v1/orgs/org-1/tokens/tok-1", nil)))
	if w.Code != http.StatusOK {
		t.Fatalf("DELETE token: %d", w.Code)
	}
}
