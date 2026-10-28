package gateway

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	chimw "github.com/go-chi/chi/v5/middleware"
	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
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

	if got := md.Get("x-caller-user-id"); len(got) != 1 || got[0] != principal.UserID {
		t.Fatalf("expected x-caller-user-id=%q, got %v", principal.UserID, got)
	}
	if got := md.Get("x-caller-kind"); len(got) != 1 || got[0] != principal.Kind {
		t.Fatalf("expected x-caller-kind=%q, got %v", principal.Kind, got)
	}
	if got := md.Get("x-caller-token-org-id"); len(got) != 1 || got[0] != principal.OrgID {
		t.Fatalf("expected x-caller-token-org-id=%q, got %v", principal.OrgID, got)
	}
	if got := md.Get("x-caller-token-permissions"); len(got) != 1 || got[0] != "org:read,members:write" {
		t.Fatalf("expected x-caller-token-permissions=%q, got %v", "org:read,members:write", got)
	}
	if got := md.Get("x-caller-session-id"); len(got) != 1 || got[0] != principal.SessionID {
		t.Fatalf("expected x-caller-session-id=%q, got %v", principal.SessionID, got)
	}
	if got := md.Get("x-request-id"); len(got) != 1 || got[0] != "req-12345" {
		t.Fatalf("expected x-request-id=req-12345, got %v", got)
	}
	if got := md.Get("x-user-agent"); len(got) != 1 || got[0] != "kr0n-test-agent" {
		t.Fatalf("expected x-user-agent=kr0n-test-agent, got %v", got)
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
			wantMsg:    "authentication service unavailable",
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
		TokenType:    "Bearer",
		ExpiresIn:    900,
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
	expectedFields := []string{"access_token", "refresh_token", "token_type", "expires_in", "user"}
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
