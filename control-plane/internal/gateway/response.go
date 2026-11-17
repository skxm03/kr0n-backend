package gateway

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/skxm03/kr0n-backend/control-plane/internal/gateway/middleware"
)

// ErrorResponseDTO represents the standard gateway error response JSON schema.
type ErrorResponseDTO struct {
	Error     string `json:"error"`
	Code      string `json:"code,omitempty"`
	RequestID string `json:"request_id,omitempty"`
}

// WriteJSON marshals v as JSON and writes it to w with the given HTTP status code.
func WriteJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// WriteErrorJSON formats and writes a standardized ErrorResponseDTO JSON response.
func WriteErrorJSON(ctx context.Context, w http.ResponseWriter, statusCode int, message, code string) {
	reqID := w.Header().Get("X-Request-ID")
	if reqID == "" && ctx != nil {
		reqID = middleware.RequestIDFromContext(ctx)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(ErrorResponseDTO{
		Error:     message,
		Code:      code,
		RequestID: reqID,
	})
}

// TranslateGRPCStatus converts a gRPC status error into kr0n standard HTTP status code and error code.
func TranslateGRPCStatus(err error) (statusCode int, message, code string) {
	st, ok := status.FromError(err)
	if !ok {
		return http.StatusInternalServerError, "internal server error", "INTERNAL_ERROR"
	}

	msg := st.Message()
	switch st.Code() {
	case codes.InvalidArgument:
		lowerMsg := strings.ToLower(msg)
		if strings.Contains(lowerMsg, "syntax") || strings.Contains(lowerMsg, "invalid character") ||
			strings.Contains(lowerMsg, "unexpected") || strings.Contains(lowerMsg, "malformed") {
			return http.StatusBadRequest, msg, "MALFORMED_JSON"
		}
		return http.StatusBadRequest, msg, "INVALID_ARGUMENT"

	case codes.Unauthenticated:
		return http.StatusUnauthorized, msg, "UNAUTHORIZED"

	case codes.PermissionDenied:
		return http.StatusForbidden, msg, "FORBIDDEN"

	case codes.NotFound:
		return http.StatusNotFound, msg, "NOT_FOUND"

	case codes.AlreadyExists:
		return http.StatusConflict, msg, "EMAIL_ALREADY_EXISTS"

	case codes.FailedPrecondition:
		if strings.Contains(strings.ToLower(msg), "not configured") {
			return http.StatusServiceUnavailable, msg, "not_configured"
		}
		return http.StatusConflict, msg, "FAILED_PRECONDITION"

	case codes.DeadlineExceeded:
		return http.StatusGatewayTimeout, "authentication service timeout", "GATEWAY_TIMEOUT"

	case codes.Unavailable:
		return http.StatusServiceUnavailable, "authentication service unavailable", "SERVICE_UNAVAILABLE"

	default:
		return http.StatusInternalServerError, "internal server error", "INTERNAL_ERROR"
	}
}

// ExtractClientIP extracts the client IP address from request context or remote address.
func ExtractClientIP(r *http.Request) string {
	if ip := middleware.ClientIPFromContext(r.Context()); ip != "" {
		return ip
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil && host != "" {
		return host
	}
	return r.RemoteAddr
}
