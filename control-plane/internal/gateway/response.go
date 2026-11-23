package gateway

import (
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"strings"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
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

	// 1. Check for rich error details returned by upstream (e.g. errdetails.ErrorInfo)
	for _, detail := range st.Details() {
		if info, ok := detail.(*errdetails.ErrorInfo); ok && info.Reason != "" {
			code = info.Reason
			break
		}
	}

	// 2. Gateway/network level timeouts and unavailabilities
	switch st.Code() {
	case codes.DeadlineExceeded:
		return http.StatusGatewayTimeout, "upstream service timeout", "GATEWAY_TIMEOUT"
	case codes.Unavailable:
		return http.StatusServiceUnavailable, "upstream service unavailable", "SERVICE_UNAVAILABLE"
	case codes.Internal, codes.Unknown:
		slog.Error("internal upstream error", "code", st.Code().String(), "raw_error", st.Message())
		if code == "" {
			code = "INTERNAL_ERROR"
		}
		return http.StatusInternalServerError, "internal server error", code
	}

	msg := st.Message()

	// 3. Dynamic error code fallback
	if code == "" {
		switch st.Code() {
		case codes.Unauthenticated:
			code = "UNAUTHORIZED"
		case codes.PermissionDenied:
			code = "FORBIDDEN"
		case codes.AlreadyExists:
			if strings.Contains(strings.ToLower(msg), "email") {
				code = "EMAIL_ALREADY_EXISTS"
			} else {
				code = "ALREADY_EXISTS"
			}
		default:
			code = toUpperSnake(st.Code().String())
		}
	}

	// 4. Map gRPC status to standard HTTP status code (RFC compliant)
	statusCode = runtime.HTTPStatusFromCode(st.Code())

	// 5. Dynamic message straight from the upstream service
	return statusCode, msg, code
}

func toUpperSnake(s string) string {
	var b strings.Builder
	for i, r := range s {
		if i > 0 && r >= 'A' && r <= 'Z' {
			b.WriteByte('_')
		}
		b.WriteRune(r)
	}
	return strings.ToUpper(b.String())
}

// ExtractClientIP extracts the client IP address from request context or remote address.
func ExtractClientIP(r *http.Request, trustedProxies ...[]*net.IPNet) string {
	var tp []*net.IPNet
	if len(trustedProxies) > 0 {
		tp = trustedProxies[0]
	}
	return middleware.ClientIP(r, tp)
}
