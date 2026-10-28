package gateway

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"strings"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	authv1 "github.com/skxm03/kr0n-backend/control-plane/gen/auth/v1"
	"github.com/skxm03/kr0n-backend/control-plane/internal/gateway/middleware"
)

// NewGatewayServeMux constructs a configured grpc-gateway ServeMux adhering to kr0n conventions:
// 1. Emits snake_case JSON fields matching current REST DTO contracts.
// 2. Propagates client IP, user agent, request ID, and authenticated Principal into gRPC metadata.
// 3. Translates gRPC status errors into kr0n ErrorResponseDTO JSON schema.
// 4. Sets HTTP 201 Created status for creation RPC responses.
func NewGatewayServeMux(trustedProxies []*net.IPNet) *runtime.ServeMux {
	return runtime.NewServeMux(
		runtime.WithMarshalerOption(runtime.MIMEWildcard, &runtime.JSONPb{
			MarshalOptions: protojson.MarshalOptions{
				UseProtoNames:   true,
				EmitUnpopulated: false,
			},
			UnmarshalOptions: protojson.UnmarshalOptions{
				DiscardUnknown: true,
			},
		}),
		runtime.WithMetadata(GatewayMetadataAnnotator(trustedProxies)),
		runtime.WithErrorHandler(GatewayErrorHandler),
		runtime.WithForwardResponseOption(func(ctx context.Context, w http.ResponseWriter, resp proto.Message) error {
			switch resp.(type) {
			case *authv1.RegisterResponse,
				*authv1.CreateOrganizationResponse,
				*authv1.AddMemberResponse,
				*authv1.CreateInviteResponse,
				*authv1.CreateAPITokenResponse:
				w.WriteHeader(http.StatusCreated)
			}
			return nil
		}),
	)
}

// GatewayMetadataAnnotator converts HTTP context, client IP, and Principal into outgoing gRPC metadata.
func GatewayMetadataAnnotator(trustedProxies []*net.IPNet) func(ctx context.Context, r *http.Request) metadata.MD {
	return func(ctx context.Context, r *http.Request) metadata.MD {
		md := metadata.MD{}

		if reqID := middleware.RequestIDFromContext(r.Context()); reqID != "" {
			md.Set("x-request-id", reqID)
		}
		if ip := extractClientIP(r); ip != "" {
			md.Set("x-client-ip", ip)
			md.Set("x-forwarded-for", ip)
		}
		if ua := r.UserAgent(); ua != "" {
			md.Set("x-user-agent", ua)
		}

		if p, ok := middleware.PrincipalFromContext(r.Context()); ok {
			if p.UserID != "" {
				md.Set("x-caller-user-id", p.UserID)
			}
			if p.Kind != "" {
				md.Set("x-caller-kind", p.Kind)
			}
			if p.OrgID != "" {
				md.Set("x-caller-token-org-id", p.OrgID)
			}
			if len(p.Permissions) > 0 {
				md.Set("x-caller-token-permissions", strings.Join(p.Permissions, ","))
			}
			if p.SessionID != "" {
				md.Set("x-caller-session-id", p.SessionID)
			}
		}

		return md
	}
}

// GatewayErrorHandler formats gRPC errors into kr0n standard ErrorResponseDTO.
func GatewayErrorHandler(ctx context.Context, mux *runtime.ServeMux, m runtime.Marshaler, w http.ResponseWriter, r *http.Request, err error) {
	st, ok := status.FromError(err)
	if !ok {
		writeErrorJSON(ctx, w, http.StatusInternalServerError, "internal server error", "INTERNAL_ERROR")
		return
	}

	statusCode := http.StatusInternalServerError
	errorCode := "INTERNAL_ERROR"
	msg := st.Message()

	switch st.Code() {
	case codes.InvalidArgument:
		statusCode = http.StatusBadRequest
		errorCode = "INVALID_ARGUMENT"
		lowerMsg := strings.ToLower(msg)
		if strings.Contains(lowerMsg, "syntax") || strings.Contains(lowerMsg, "invalid character") || strings.Contains(lowerMsg, "unexpected") || strings.Contains(lowerMsg, "malformed") {
			errorCode = "MALFORMED_JSON"
		}
	case codes.Unauthenticated:
		statusCode = http.StatusUnauthorized
		errorCode = "UNAUTHORIZED"
	case codes.PermissionDenied:
		statusCode = http.StatusForbidden
		errorCode = "FORBIDDEN"
	case codes.NotFound:
		statusCode = http.StatusNotFound
		errorCode = "NOT_FOUND"
	case codes.AlreadyExists:
		statusCode = http.StatusConflict
		errorCode = "EMAIL_ALREADY_EXISTS"
	case codes.FailedPrecondition:
		if strings.Contains(strings.ToLower(msg), "not configured") {
			statusCode = http.StatusServiceUnavailable
			errorCode = "not_configured"
		} else {
			statusCode = http.StatusConflict
			errorCode = "FAILED_PRECONDITION"
		}
	case codes.DeadlineExceeded:
		statusCode = http.StatusGatewayTimeout
		errorCode = "GATEWAY_TIMEOUT"
		msg = "authentication service timeout"
	case codes.Unavailable:
		statusCode = http.StatusServiceUnavailable
		errorCode = "SERVICE_UNAVAILABLE"
		msg = "authentication service unavailable"
	default:
		statusCode = http.StatusInternalServerError
		errorCode = "INTERNAL_ERROR"
		msg = "internal server error"
	}

	writeErrorJSON(ctx, w, statusCode, msg, errorCode)
}

func writeErrorJSON(ctx context.Context, w http.ResponseWriter, statusCode int, message, code string) {
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

