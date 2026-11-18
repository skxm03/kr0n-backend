package gateway

import (
	"context"
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	"github.com/skxm03/kr0n-backend/control-plane/internal/gateway/middleware"
)

// NewGatewayServeMux constructs a configured grpc-gateway ServeMux adhering to kr0n conventions:
// 1. Emits snake_case JSON fields matching current REST DTO contracts.
// 2. Propagates client IP, user agent, request ID, and authenticated Principal into gRPC metadata.
// 3. Translates gRPC status errors into kr0n ErrorResponseDTO JSON schema.
// 4. Sets HTTP 201 Created status for creation RPC responses dynamically.
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
		runtime.WithForwardResponseOption(GatewayResponseModifier),
	)
}

// GatewayResponseModifier handles HTTP response status code customization dynamically:
// 1. Honors explicit HTTP status codes sent by upstream services via gRPC response headers ("x-http-code" / "x-http-status").
// 2. Automatically sets HTTP 201 Created for resource creation responses by protobuf convention (Create*, Add*, Register*).
func GatewayResponseModifier(ctx context.Context, w http.ResponseWriter, resp proto.Message) error {
	// 1. Check if upstream service explicitly requested an HTTP status code via gRPC metadata
	if md, ok := runtime.ServerMetadataFromContext(ctx); ok {
		for _, key := range []string{"x-http-code", "x-http-status"} {
			if vals := md.HeaderMD.Get(key); len(vals) > 0 {
				if code, err := strconv.Atoi(vals[0]); err == nil && code >= 200 && code < 600 {
					w.WriteHeader(code)
					return nil
				}
			}
		}
	}

	// 2. Dynamic proto convention: any Create* or Add* resource response returns 201 Created
	if resp != nil {
		msgName := string(resp.ProtoReflect().Descriptor().Name())
		if isCreationResponse(msgName) {
			w.WriteHeader(http.StatusCreated)
			return nil
		}
	}

	return nil
}

func isCreationResponse(name string) bool {
	return strings.HasPrefix(name, "Create") ||
		strings.HasPrefix(name, "Add") ||
		name == "RegisterResponse" ||
		name == "CompleteGitHubInstallationResponse"
}

// GatewayMetadataAnnotator converts HTTP context, client IP, and Principal into outgoing gRPC metadata.
func GatewayMetadataAnnotator(trustedProxies []*net.IPNet) func(ctx context.Context, r *http.Request) metadata.MD {
	return func(ctx context.Context, r *http.Request) metadata.MD {
		md := metadata.MD{}

		if reqID := middleware.RequestIDFromContext(r.Context()); reqID != "" {
			md.Set("x-request-id", reqID)
		}
		if ip := ExtractClientIP(r, trustedProxies); ip != "" {
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
	statusCode, msg, errorCode := TranslateGRPCStatus(err)
	WriteErrorJSON(ctx, w, statusCode, msg, errorCode)
}
