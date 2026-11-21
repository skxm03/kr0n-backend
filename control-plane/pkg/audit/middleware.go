package audit

import (
	"context"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// RequestMetadata holds request-scoped identity extracted by host services.
type RequestMetadata struct {
	OrganizationID *uuid.UUID
	Actor          Actor
	Target         Target
	Action         string
	RequestID      string
	ClientIP       string
}

// HTTPExtractor extracts caller identity and target resource details from an HTTP request.
type HTTPExtractor func(r *http.Request) RequestMetadata

// HTTPMiddlewareConfig configures automated HTTP audit emission.
type HTTPMiddlewareConfig struct {
	ServiceName string
	Extractor   HTTPExtractor
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

// HTTPMiddleware returns a standard net/http middleware that emits an audit event after each request completes.
func HTTPMiddleware(emitter Emitter, cfg HTTPMiddlewareConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		if emitter == nil {
			return next
		}
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(rec, r)

			var extracted RequestMetadata
			if cfg.Extractor != nil {
				extracted = cfg.Extractor(r)
			}

			action := strings.TrimSpace(extracted.Action)
			if action == "" {
				action = ActionHTTPRequest.String()
			}
			targetType := strings.TrimSpace(extracted.Target.Type)
			if targetType == "" {
				targetType = TargetTypeHTTPRoute
			}
			targetID := strings.TrimSpace(extracted.Target.ID)
			if targetID == "" {
				targetID = r.URL.Path
			}

			outcome := StatusSuccess
			if rec.status == http.StatusUnauthorized || rec.status == http.StatusForbidden {
				outcome = StatusDenied
			} else if rec.status >= 400 {
				outcome = StatusFailure
			}

			var ipPtr *net.IP
			rawIP := strings.TrimSpace(extracted.ClientIP)
			if rawIP == "" {
				rawIP, _, _ = net.SplitHostPort(strings.TrimSpace(r.RemoteAddr))
				if rawIP == "" {
					rawIP = strings.TrimSpace(r.RemoteAddr)
				}
			}
			if parsed := net.ParseIP(rawIP); parsed != nil {
				ipPtr = &parsed
			}

			var uaPtr *string
			if ua := strings.TrimSpace(r.UserAgent()); ua != "" {
				uaPtr = &ua
			}

			reqID := strings.TrimSpace(extracted.RequestID)
			if reqID == "" {
				reqID = strings.TrimSpace(r.Header.Get("X-Request-Id"))
			}

			_ = emitter.Emit(r.Context(), Event{
				Service:        cfg.ServiceName,
				Action:         action,
				Status:         outcome,
				OrganizationID: extracted.OrganizationID,
				Actor:          extracted.Actor,
				Target: Target{
					Type: targetType,
					ID:   targetID,
					Name: extracted.Target.Name,
				},
				ClientContext: ClientContext{
					IPAddress: ipPtr,
					UserAgent: uaPtr,
					RequestID: reqID,
				},
				Metadata: map[string]any{
					"method":      r.Method,
					"path":        r.URL.Path,
					"status":      rec.status,
					"duration_ms": time.Since(start).Milliseconds(),
				},
				Timestamp: start.UTC(),
			})
		})
	}
}

// GRPCExtractor allows a gRPC server to enrich the emitted audit event from the RPC request/context.
type GRPCExtractor func(ctx context.Context, fullMethod string, req any) RequestMetadata

// UnaryServerInterceptor returns a gRPC UnaryServerInterceptor that emits an audit event for each RPC invocation.
func UnaryServerInterceptor(emitter Emitter, serviceName string, extractor GRPCExtractor) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if emitter == nil {
			return handler(ctx, req)
		}
		start := time.Now()
		resp, err := handler(ctx, req)

		var extracted RequestMetadata
		if extractor != nil {
			extracted = extractor(ctx, info.FullMethod, req)
		}

		if md, ok := metadata.FromIncomingContext(ctx); ok {
			if extracted.OrganizationID == nil {
				if rawOrg := firstMD(md, "x-passport-org-id"); rawOrg != "" {
					if oid, err := uuid.Parse(rawOrg); err == nil {
						extracted.OrganizationID = &oid
					}
				}
			}
			if extracted.Actor.UserID == nil {
				if rawUser := firstMD(md, "x-passport-user-id"); rawUser != "" {
					if uid, err := uuid.Parse(rawUser); err == nil {
						extracted.Actor.UserID = &uid
					}
				}
			}
			if extracted.Actor.Type == "" {
				if kind := firstMD(md, "x-passport-kind"); kind != "" {
					extracted.Actor.Type = kind
				} else if extracted.Actor.UserID != nil {
					extracted.Actor.Type = ActorTypeUser
				}
			}
		}

		action := strings.TrimSpace(extracted.Action)
		if action == "" {
			action = ActionGRPCCall.String()
		}
		targetType := strings.TrimSpace(extracted.Target.Type)
		if targetType == "" {
			targetType = TargetTypeGRPCMethod
		}
		targetID := strings.TrimSpace(extracted.Target.ID)
		if targetID == "" {
			targetID = info.FullMethod
		}

		outcome := StatusSuccess
		grpcCode := codes.OK
		if err != nil {
			grpcCode = status.Code(err)
			if grpcCode == codes.Unauthenticated || grpcCode == codes.PermissionDenied {
				outcome = StatusDenied
			} else {
				outcome = StatusFailure
			}
		}

		var ipPtr *net.IP
		var uaPtr *string
		reqID := strings.TrimSpace(extracted.RequestID)

		if md, ok := metadata.FromIncomingContext(ctx); ok {
			if rawIP := firstMD(md, "x-client-ip"); rawIP != "" {
				if parsed := net.ParseIP(rawIP); parsed != nil {
					ipPtr = &parsed
				}
			}
			if ua := firstMD(md, "x-user-agent"); ua != "" {
				uaPtr = &ua
			}
			if reqID == "" {
				reqID = firstMD(md, "x-request-id")
			}
		}

		_ = emitter.Emit(ctx, Event{
			Service:        serviceName,
			Action:         action,
			Status:         outcome,
			OrganizationID: extracted.OrganizationID,
			Actor:          extracted.Actor,
			Target: Target{
				Type: targetType,
				ID:   targetID,
				Name: extracted.Target.Name,
			},
			ClientContext: ClientContext{
				IPAddress: ipPtr,
				UserAgent: uaPtr,
				RequestID: reqID,
			},
			Metadata: map[string]any{
				"grpc_method": info.FullMethod,
				"grpc_code":   grpcCode.String(),
				"duration_ms": time.Since(start).Milliseconds(),
			},
			Timestamp: start.UTC(),
		})

		return resp, err
	}
}

func firstMD(md metadata.MD, key string) string {
	vals := md.Get(key)
	if len(vals) == 0 {
		return ""
	}
	return strings.TrimSpace(vals[0])
}
