package gateway

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	chimw "github.com/go-chi/chi/v5/middleware"
	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	authv1 "github.com/skxm03/kr0n-backend/control-plane/gen/auth/v1"
	"github.com/skxm03/kr0n-backend/control-plane/internal/gateway/middleware"
)

func TestGatewayMetadataAnnotator(t *testing.T) {
	annotator := GatewayMetadataAnnotator(nil)

	principal := &middleware.Principal{
		UserID:      "018f3a5e-6c8a-7292-9111-bf74c2d67d71",
		Kind:        middleware.PrincipalKindAPIToken,
		OrgID:       "018f3a5e-6c8a-7292-9111-bf74c2d67d72",
		Permissions: []string{"org:read", "members:write"},
		SessionID:   "018f3a5e-6c8a-7292-9111-bf74c2d67d73",
	}

	ctx := middleware.WithPrincipal(context.Background(), principal)
	ctx = context.WithValue(ctx, chimw.RequestIDKey, "req-12345")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/orgs/123", nil)
	req.Header.Set("User-Agent", "kr0n-test-agent")
	req.Header.Set("X-Forwarded-For", "203.0.113.195")
	req = req.WithContext(ctx)

	md := annotator(req.Context(), req)

	if got := md.Get("x-caller-user-id"); len(got) != 0 {
		t.Fatalf("expected no x-caller-user-id header in metadata, got %v", got)
	}
	if got := md.Get("x-caller-kind"); len(got) != 0 {
		t.Fatalf("expected no x-caller-kind header in metadata, got %v", got)
	}
	if got := md.Get("x-caller-session-id"); len(got) != 0 {
		t.Fatalf("expected no x-caller-session-id header in metadata, got %v", got)
	}
	if got := md.Get("x-request-id"); len(got) != 1 || got[0] != "req-12345" {
		t.Fatalf("expected x-request-id=req-12345, got %v", got)
	}
	if got := md.Get("x-user-agent"); len(got) != 1 || got[0] != "kr0n-test-agent" {
		t.Fatalf("expected x-user-agent=kr0n-test-agent, got %v", got)
	}
}

func TestGatewayMetadataAnnotator_TrustedProxyClientIP(t *testing.T) {
	_, lbNet, _ := net.ParseCIDR("10.0.0.0/8")
	annotator := GatewayMetadataAnnotator([]*net.IPNet{lbNet})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/test", nil)
	req.RemoteAddr = "10.0.0.1:54321" // Trusted proxy load balancer peer
	req.Header.Set("X-Forwarded-For", "203.0.113.195")

	md := annotator(req.Context(), req)

	if got := md.Get("x-client-ip"); len(got) != 1 || got[0] != "203.0.113.195" {
		t.Fatalf("expected x-client-ip to be 203.0.113.195, got %v", got)
	}
	if got := md.Get("x-forwarded-for"); len(got) != 1 || got[0] != "203.0.113.195" {
		t.Fatalf("expected x-forwarded-for to be 203.0.113.195, got %v", got)
	}
}

func TestGatewayErrorHandler(t *testing.T) {
	tests := []struct {
		name       string
		err        error
		wantStatus int
		wantCode   string
		wantMsg    string
	}{
		{
			name:       "not found",
			err:        status.Error(codes.NotFound, "organization not found"),
			wantStatus: http.StatusNotFound,
			wantCode:   "NOT_FOUND",
			wantMsg:    "organization not found",
		},
		{
			name:       "already exists",
			err:        status.Error(codes.AlreadyExists, "email already registered"),
			wantStatus: http.StatusConflict,
			wantCode:   "EMAIL_ALREADY_EXISTS",
			wantMsg:    "email already registered",
		},
		{
			name:       "unauthenticated",
			err:        status.Error(codes.Unauthenticated, "invalid credentials"),
			wantStatus: http.StatusUnauthorized,
			wantCode:   "UNAUTHORIZED",
			wantMsg:    "invalid credentials",
		},
		{
			name:       "forbidden",
			err:        status.Error(codes.PermissionDenied, "insufficient privileges"),
			wantStatus: http.StatusForbidden,
			wantCode:   "FORBIDDEN",
			wantMsg:    "insufficient privileges",
		},
		{
			name:       "invalid argument",
			err:        status.Error(codes.InvalidArgument, "name is required"),
			wantStatus: http.StatusBadRequest,
			wantCode:   "INVALID_ARGUMENT",
			wantMsg:    "name is required",
		},
		{
			name:       "service unavailable",
			err:        status.Error(codes.Unavailable, "backend down"),
			wantStatus: http.StatusServiceUnavailable,
			wantCode:   "SERVICE_UNAVAILABLE",
			wantMsg:    "upstream service unavailable",
		},
		{
			name:       "already exists generic slug",
			err:        status.Error(codes.AlreadyExists, "organization slug already exists"),
			wantStatus: http.StatusConflict,
			wantCode:   "ALREADY_EXISTS",
			wantMsg:    "organization slug already exists",
		},
		{
			name: "custom upstream error detail reason",
			err: func() error {
				st := status.New(codes.FailedPrecondition, "payment source required")
				stWithDetails, _ := st.WithDetails(&errdetails.ErrorInfo{Reason: "PAYMENT_METHOD_REQUIRED"})
				return stWithDetails.Err()
			}(),
			wantStatus: http.StatusBadRequest,
			wantCode:   "PAYMENT_METHOD_REQUIRED",
			wantMsg:    "payment source required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodGet, "/test", nil)
			ctx := context.WithValue(r.Context(), chimw.RequestIDKey, "req-err-456")

			GatewayErrorHandler(ctx, nil, nil, w, r, tt.err)

			if w.Code != tt.wantStatus {
				t.Fatalf("expected status %d, got %d", tt.wantStatus, w.Code)
			}

			var resp ErrorResponseDTO
			if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
				t.Fatalf("failed to decode response: %v", err)
			}
			if resp.Code != tt.wantCode {
				t.Fatalf("expected code %q, got %q", tt.wantCode, resp.Code)
			}
			if resp.Error != tt.wantMsg {
				t.Fatalf("expected error %q, got %q", tt.wantMsg, resp.Error)
			}
			if resp.RequestID != "req-err-456" {
				t.Fatalf("expected request_id 'req-err-456', got %q", resp.RequestID)
			}
		})
	}
}

func TestNewGatewayServeMux_SnakeCaseMarshaler(t *testing.T) {
	mux := NewGatewayServeMux(nil)
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	marshaler, _ := runtime.MarshalerForRequest(mux, req)

	loginResp := &authv1.LoginResponse{
		AccessToken:  "jwt-access-token",
		RefreshToken: "jwt-refresh-token",
		User: &authv1.LoginUser{
			Id:          "u-1",
			Email:       "alice@example.com",
			DisplayName: "Alice",
			Status:      "active",
		},
	}

	bytes, err := marshaler.Marshal(loginResp)
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}

	var jsonMap map[string]any
	if err := json.Unmarshal(bytes, &jsonMap); err != nil {
		t.Fatalf("json unmarshal error: %v", err)
	}

	// Verify snake_case field names are emitted
	expectedFields := []string{"access_token", "refresh_token", "user"}
	for _, field := range expectedFields {
		if _, exists := jsonMap[field]; !exists {
			t.Fatalf("expected snake_case field %q in marshaled JSON, but was missing: %s", field, string(bytes))
		}
	}

	userMap, ok := jsonMap["user"].(map[string]any)
	if !ok {
		t.Fatalf("expected user to be a map: %v", jsonMap["user"])
	}
	if userMap["display_name"] != "Alice" {
		t.Fatalf("expected user.display_name='Alice', got %v", userMap["display_name"])
	}
}

func TestGatewayResponseModifier(t *testing.T) {
	t.Run("creation response returns 201 Created", func(t *testing.T) {
		rec := httptest.NewRecorder()
		regResp := &authv1.RegisterResponse{UserId: "u-123"}
		if err := GatewayResponseModifier(context.Background(), rec, regResp); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if rec.Code != http.StatusCreated {
			t.Fatalf("expected 201 Created, got %d", rec.Code)
		}
	})

	t.Run("non-creation response leaves status code unset for default 200", func(t *testing.T) {
		rec := httptest.NewRecorder()
		loginResp := &authv1.LoginResponse{AccessToken: "token"}
		if err := GatewayResponseModifier(context.Background(), rec, loginResp); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if rec.Code != http.StatusOK {
			t.Fatalf("expected default 200 OK, got %d", rec.Code)
		}
	})

	t.Run("login response sets HttpOnly cookies and wipes tokens from response message", func(t *testing.T) {
		rec := httptest.NewRecorder()
		loginResp := &authv1.LoginResponse{
			AccessToken:  "secret-access-token",
			RefreshToken: "secret-refresh-token",
		}

		if err := GatewayResponseModifier(context.Background(), rec, loginResp); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Body fields must be strictly wiped out
		if loginResp.AccessToken != "" {
			t.Fatalf("expected AccessToken to be wiped from response body, got %q", loginResp.AccessToken)
		}
		if loginResp.RefreshToken != "" {
			t.Fatalf("expected RefreshToken to be wiped from response body, got %q", loginResp.RefreshToken)
		}

		// Cookies must be set with HttpOnly, Path=/, SameSite=Lax
		cookies := rec.Result().Cookies()
		var foundAccess, foundRefresh *http.Cookie
		for _, c := range cookies {
			if c.Name == AccessTokenCookieName {
				foundAccess = c
			}
			if c.Name == RefreshTokenCookieName {
				foundRefresh = c
			}
		}

		if foundAccess == nil {
			t.Fatal("expected access_token cookie to be set")
		}
		if foundAccess.Value != "secret-access-token" || !foundAccess.HttpOnly || foundAccess.Path != "/" || foundAccess.MaxAge != 900 {
			t.Fatalf("unexpected access_token cookie attributes: %+v", foundAccess)
		}

		if foundRefresh == nil {
			t.Fatal("expected refresh_token cookie to be set")
		}
		if foundRefresh.Value != "secret-refresh-token" || !foundRefresh.HttpOnly || foundRefresh.Path != "/" || foundRefresh.MaxAge != 30*24*3600 {
			t.Fatalf("unexpected refresh_token cookie attributes: %+v", foundRefresh)
		}
	})

	t.Run("refresh response sets HttpOnly cookies and wipes tokens from response message", func(t *testing.T) {
		rec := httptest.NewRecorder()
		refResp := &authv1.RefreshResponse{
			AccessToken:  "new-access-token",
			RefreshToken: "new-refresh-token",
		}

		if err := GatewayResponseModifier(context.Background(), rec, refResp); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if refResp.AccessToken != "" || refResp.RefreshToken != "" {
			t.Fatalf("expected tokens wiped from body, got access=%q refresh=%q", refResp.AccessToken, refResp.RefreshToken)
		}

		cookies := rec.Result().Cookies()
		if len(cookies) < 2 {
			t.Fatalf("expected at least 2 cookies, got %d", len(cookies))
		}
	})

	t.Run("logout response clears authentication cookies", func(t *testing.T) {
		rec := httptest.NewRecorder()
		logoutResp := &authv1.LogoutResponse{Message: "session revoked"}

		if err := GatewayResponseModifier(context.Background(), rec, logoutResp); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		cookies := rec.Result().Cookies()
		for _, c := range cookies {
			if c.Name == AccessTokenCookieName || c.Name == RefreshTokenCookieName {
				if c.MaxAge != -1 || c.Value != "" {
					t.Fatalf("expected cookie %s to be cleared, got MaxAge=%d Value=%q", c.Name, c.MaxAge, c.Value)
				}
			}
		}
	})

	t.Run("complete github oauth response sets cookies and redirects to FRONTEND_URL", func(t *testing.T) {
		rec := httptest.NewRecorder()
		ghResp := &authv1.CompleteGitHubOAuthResponse{
			AccessToken:  "gh-access-token",
			RefreshToken: "gh-refresh-token",
		}

		t.Setenv("FRONTEND_URL", "http://localhost:3000")
		if err := GatewayResponseModifier(context.Background(), rec, ghResp); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if rec.Code != http.StatusFound {
			t.Fatalf("expected 302 Found, got %d", rec.Code)
		}
		if loc := rec.Header().Get("Location"); loc != "http://localhost:3000" {
			t.Fatalf("expected Location header http://localhost:3000, got %q", loc)
		}

		// Tokens wiped from response message
		if ghResp.AccessToken != "" || ghResp.RefreshToken != "" {
			t.Fatal("expected tokens to be wiped from response body")
		}

		// Cookies set
		cookies := rec.Result().Cookies()
		cookieMap := make(map[string]*http.Cookie)
		for _, c := range cookies {
			cookieMap[c.Name] = c
		}
		if cookieMap[AccessTokenCookieName] == nil || cookieMap[AccessTokenCookieName].Value != "gh-access-token" {
			t.Fatal("expected access_token cookie to be set")
		}
		if cookieMap[RefreshTokenCookieName] == nil || cookieMap[RefreshTokenCookieName].Value != "gh-refresh-token" {
			t.Fatal("expected refresh_token cookie to be set")
		}
	})

	t.Run("start google oauth response sets google_oauth_verifier cookie", func(t *testing.T) {
		rec := httptest.NewRecorder()
		resp := &authv1.StartGoogleOAuthResponse{
			AuthorizeUrl: "https://accounts.google.com/o/oauth2/v2/auth?client_id=123",
			State:        "state-123",
			CodeVerifier: "verifier-xyz-123",
		}

		if err := GatewayResponseModifier(context.Background(), rec, resp); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		cookies := rec.Result().Cookies()
		var verifierCookie *http.Cookie
		for _, c := range cookies {
			if c.Name == "google_oauth_verifier" {
				verifierCookie = c
				break
			}
		}
		if verifierCookie == nil || verifierCookie.Value != "verifier-xyz-123" {
			t.Fatalf("expected google_oauth_verifier cookie, got %v", verifierCookie)
		}
	})

	t.Run("complete google oauth response sets cookies and redirects to FRONTEND_URL", func(t *testing.T) {
		rec := httptest.NewRecorder()
		resp := &authv1.CompleteGoogleOAuthResponse{
			AccessToken:  "google-access-token",
			RefreshToken: "google-refresh-token",
		}

		t.Setenv("FRONTEND_URL", "http://localhost:3000")
		if err := GatewayResponseModifier(context.Background(), rec, resp); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if rec.Code != http.StatusFound {
			t.Fatalf("expected 302 Found, got %d", rec.Code)
		}
		if loc := rec.Header().Get("Location"); loc != "http://localhost:3000" {
			t.Fatalf("expected Location header http://localhost:3000, got %q", loc)
		}

		if resp.AccessToken != "" || resp.RefreshToken != "" {
			t.Fatal("expected tokens to be wiped from response body")
		}

		cookies := rec.Result().Cookies()
		cookieMap := make(map[string]*http.Cookie)
		for _, c := range cookies {
			cookieMap[c.Name] = c
		}
		if cookieMap[AccessTokenCookieName] == nil || cookieMap[AccessTokenCookieName].Value != "google-access-token" {
			t.Fatal("expected access_token cookie to be set")
		}
		if cookieMap[RefreshTokenCookieName] == nil || cookieMap[RefreshTokenCookieName].Value != "google-refresh-token" {
			t.Fatal("expected refresh_token cookie to be set")
		}
		if cookieMap["google_oauth_verifier"] == nil || cookieMap["google_oauth_verifier"].MaxAge != -1 {
			t.Fatal("expected google_oauth_verifier cookie to be cleared")
		}
	})
}

func TestGatewayMetadataAnnotator_RefreshTokenCookie(t *testing.T) {
	annotator := GatewayMetadataAnnotator(nil)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/refresh", nil)
	req.AddCookie(&http.Cookie{
		Name:  RefreshTokenCookieName,
		Value: "cookie-refresh-token-123",
	})

	md := annotator(context.Background(), req)
	tokens := md.Get("x-refresh-token")
	if len(tokens) != 1 || tokens[0] != "cookie-refresh-token-123" {
		t.Fatalf("expected x-refresh-token in gRPC metadata to be cookie-refresh-token-123, got %v", tokens)
	}
}

func TestGatewayMetadataAnnotator_GoogleOAuthVerifierCookie(t *testing.T) {
	annotator := GatewayMetadataAnnotator(nil)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/google/callback?code=abc", nil)
	req.AddCookie(&http.Cookie{
		Name:  "google_oauth_verifier",
		Value: "test-google-verifier-456",
	})

	md := annotator(context.Background(), req)
	verifiers := md.Get("x-code-verifier")
	if len(verifiers) != 1 || verifiers[0] != "test-google-verifier-456" {
		t.Fatalf("expected x-code-verifier in gRPC metadata to be test-google-verifier-456, got %v", verifiers)
	}
}
