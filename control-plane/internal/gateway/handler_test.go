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
}

func (m *mockAuthClient) Register(ctx context.Context, in *authv1.RegisterRequest, opts ...grpc.CallOption) (*authv1.RegisterResponse, error) {
	if m.registerFunc != nil {
		return m.registerFunc(ctx, in, opts...)
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
