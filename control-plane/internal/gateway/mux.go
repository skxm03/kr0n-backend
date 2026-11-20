package gateway

import (
	"context"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	authv1 "github.com/skxm03/kr0n-backend/control-plane/gen/auth/v1"
	"github.com/skxm03/kr0n-backend/control-plane/internal/gateway/middleware"
)

const (
	AccessTokenCookieName  = "access_token"
	RefreshTokenCookieName = "refresh_token"
)

// SetAuthCookies writes HttpOnly, SameSite cookies for access_token and refresh_token,
// ensuring tokens are never exposed in JavaScript or HTTP response bodies (mitigating XSS).
func SetAuthCookies(w http.ResponseWriter, accessToken, refreshToken string, expiresIn int32) {
	if accessToken != "" {
		maxAge := int(expiresIn)
		if maxAge <= 0 {
			maxAge = 900 // default 15 minutes
		}
		http.SetCookie(w, &http.Cookie{
			Name:     AccessTokenCookieName,
			Value:    accessToken,
			Path:     "/",
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
			MaxAge:   maxAge,
		})
	}
	if refreshToken != "" {
		http.SetCookie(w, &http.Cookie{
			Name:     RefreshTokenCookieName,
			Value:    refreshToken,
			Path:     "/",
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
			MaxAge:   30 * 24 * 3600, // 30 days
		})
	}
}

// ClearAuthCookies invalidates access_token and refresh_token cookies upon logout.
func ClearAuthCookies(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     AccessTokenCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
		Expires:  time.Unix(0, 0),
	})
	http.SetCookie(w, &http.Cookie{
		Name:     RefreshTokenCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
		Expires:  time.Unix(0, 0),
	})
}

// NewGatewayServeMux constructs a configured grpc-gateway ServeMux adhering to kr0n conventions:
// 1. Emits snake_case JSON fields matching current REST DTO contracts.
// 2. Propagates client IP, user agent, request ID, refresh token cookie, and authenticated Principal into gRPC metadata.
// 3. Translates gRPC status errors into kr0n ErrorResponseDTO JSON schema.
// 4. Sets HTTP 201 Created status for creation RPC responses dynamically.
// 5. Delivers authentication tokens strictly via HttpOnly cookies and wipes them from response bodies.
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

// GatewayResponseModifier handles HTTP response customization dynamically:
// 1. Delivers authentication tokens strictly via HttpOnly cookies and zeroes them from HTTP bodies.
// 2. Honors explicit HTTP status codes sent by upstream services via gRPC response headers ("x-http-code" / "x-http-status").
// 3. Automatically sets HTTP 201 Created for resource creation responses by protobuf convention (Create*, Add*, Register*).
func GatewayResponseModifier(ctx context.Context, w http.ResponseWriter, resp proto.Message) error {
	// 1. Intercept auth responses and deliver tokens strictly via HttpOnly cookies
	if resp != nil {
		switch m := resp.(type) {
		case *authv1.LoginResponse:
			if m.AccessToken != "" || m.RefreshToken != "" {
				SetAuthCookies(w, m.AccessToken, m.RefreshToken, m.ExpiresIn)
				m.AccessToken = ""
				m.RefreshToken = ""
			}
		case *authv1.RefreshResponse:
			if m.AccessToken != "" || m.RefreshToken != "" {
				SetAuthCookies(w, m.AccessToken, m.RefreshToken, m.ExpiresIn)
				m.AccessToken = ""
				m.RefreshToken = ""
			}
		case *authv1.CompleteGitHubOAuthResponse:
			if m.AccessToken != "" || m.RefreshToken != "" {
				SetAuthCookies(w, m.AccessToken, m.RefreshToken, m.ExpiresIn)
				m.AccessToken = ""
				m.RefreshToken = ""
			}
		case *authv1.LogoutResponse:
			ClearAuthCookies(w)
		}
	}

	// 2. Check if upstream service explicitly requested an HTTP status code via gRPC metadata
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

	// 3. Dynamic proto convention: any Create* or Add* resource response returns 201 Created
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

// GatewayMetadataAnnotator converts HTTP context, client IP, and request tracing into outgoing gRPC metadata.
// Caller identity is propagated exclusively via typed protobuf passports (CallerPrincipal) in gRPC payload.
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
		if c, err := r.Cookie(RefreshTokenCookieName); err == nil && strings.TrimSpace(c.Value) != "" {
			md.Set("x-refresh-token", strings.TrimSpace(c.Value))
		}

		return md
	}
}

// GatewayErrorHandler formats gRPC errors into kr0n standard ErrorResponseDTO.
func GatewayErrorHandler(ctx context.Context, mux *runtime.ServeMux, m runtime.Marshaler, w http.ResponseWriter, r *http.Request, err error) {
	statusCode, msg, errorCode := TranslateGRPCStatus(err)
	WriteErrorJSON(ctx, w, statusCode, msg, errorCode)
}
