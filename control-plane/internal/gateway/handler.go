package gateway

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	authv1 "github.com/skxm03/kr0n-backend/control-plane/gen/auth/v1"
)

// AuthServiceClient defines the gRPC client contract required by the Gateway handler.
type AuthServiceClient interface {
	Register(ctx context.Context, in *authv1.RegisterRequest, opts ...grpc.CallOption) (*authv1.RegisterResponse, error)
}

// RegisterRequestDTO represents the client registration request JSON schema.
type RegisterRequestDTO struct {
	Email       string `json:"email"`
	Password    string `json:"password"`
	DisplayName string `json:"display_name"`
}

// RegisterResponseDTO represents the successful client registration response JSON schema.
type RegisterResponseDTO struct {
	UserID      string `json:"user_id"`
	Email       string `json:"email"`
	DisplayName string `json:"display_name"`
	Status      string `json:"status"`
	CreatedAt   string `json:"created_at"`
}

// ErrorResponseDTO represents standard error response JSON format.
type ErrorResponseDTO struct {
	Error string `json:"error"`
	Code  string `json:"code,omitempty"`
}

// Handler handles HTTP requests for the API Gateway.
type Handler struct {
	authClient AuthServiceClient
}

// NewHandler creates a new API Gateway Handler.
func NewHandler(authClient AuthServiceClient) *Handler {
	return &Handler{
		authClient: authClient,
	}
}

// Register handles user registration HTTP POST requests.
func (h *Handler) Register(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.writeError(w, http.StatusMethodNotAllowed, "method not allowed", "METHOD_NOT_ALLOWED")
		return
	}

	contentType := r.Header.Get("Content-Type")
	if !strings.HasPrefix(strings.ToLower(contentType), "application/json") {
		h.writeError(w, http.StatusUnsupportedMediaType, "content-type must be application/json", "UNSUPPORTED_MEDIA_TYPE")
		return
	}

	// Limit request payload to 1MB to prevent memory exhaustion
	r.Body = http.MaxBytesReader(w, r.Body, 1048576)

	var req RegisterRequestDTO
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, "invalid request body", "MALFORMED_JSON")
		return
	}

	if strings.TrimSpace(req.Email) == "" || req.Password == "" || strings.TrimSpace(req.DisplayName) == "" {
		h.writeError(w, http.StatusBadRequest, "email, password, and display_name are required", "INVALID_ARGUMENT")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	grpcResp, err := h.authClient.Register(ctx, &authv1.RegisterRequest{
		Email:       req.Email,
		Password:    req.Password,
		DisplayName: req.DisplayName,
	})
	if err != nil {
		st, ok := status.FromError(err)
		if !ok {
			h.writeError(w, http.StatusInternalServerError, "internal server error", "INTERNAL_ERROR")
			return
		}

		switch st.Code() {
		case codes.AlreadyExists:
			h.writeError(w, http.StatusConflict, st.Message(), "EMAIL_ALREADY_EXISTS")
		case codes.InvalidArgument:
			h.writeError(w, http.StatusBadRequest, st.Message(), "INVALID_ARGUMENT")
		case codes.DeadlineExceeded:
			h.writeError(w, http.StatusGatewayTimeout, "authentication service timeout", "GATEWAY_TIMEOUT")
		case codes.Unavailable:
			h.writeError(w, http.StatusServiceUnavailable, "authentication service unavailable", "SERVICE_UNAVAILABLE")
		default:
			h.writeError(w, http.StatusInternalServerError, "internal server error", "INTERNAL_ERROR")
		}
		return
	}

	resp := RegisterResponseDTO{
		UserID:      grpcResp.GetUserId(),
		Email:       grpcResp.GetEmail(),
		DisplayName: grpcResp.GetDisplayName(),
		Status:      grpcResp.GetStatus(),
		CreatedAt:   grpcResp.GetCreatedAt().AsTime().Format(time.RFC3339),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(resp)
}

func (h *Handler) writeError(w http.ResponseWriter, statusCode int, message, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(ErrorResponseDTO{
		Error: message,
		Code:  code,
	})
}
