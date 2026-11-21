package builtins

import (
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
	"github.com/google/uuid"

	"github.com/skxm03/kr0n-backend/control-plane/internal/gateway/middleware"
	pkgAudit "github.com/skxm03/kr0n-backend/control-plane/pkg/audit"
)

// NewAuditLogFactory creates a MiddlewareFactory that records security audit logs
// and emits canonical audit events to RabbitMQ via pkg/audit when an AuditEmitter is configured.
//
// Supported optional YAML config parameters:
//   - action (string): explicit action name override (default: "gateway.http.<method>")
//   - target_type / resource_type (string): target resource type override (default: "http_route")
//   - service (string): service name override (default: "gateway")
//   - include_options (bool): whether to audit CORS preflight OPTIONS requests (default: false)
func NewAuditLogFactory(deps SharedDeps) middleware.MiddlewareFactory {
	return func(cfg map[string]any) (middleware.Middleware, error) {
		logger := deps.Logger
		emitter := deps.AuditEmitter
		if logger == nil && emitter == nil {
			return func(next http.Handler) http.Handler { return next }, nil
		}

		customAction := ""
		customTargetType := pkgAudit.TargetTypeHTTPRoute
		serviceName := pkgAudit.ServiceGateway
		includeOptions := false

		if cfg != nil {
			if v, ok := cfg["action"].(string); ok && strings.TrimSpace(v) != "" {
				customAction = strings.TrimSpace(v)
			}
			if v, ok := cfg["target_type"].(string); ok && strings.TrimSpace(v) != "" {
				customTargetType = strings.TrimSpace(v)
			} else if v, ok := cfg["resource_type"].(string); ok && strings.TrimSpace(v) != "" {
				customTargetType = strings.TrimSpace(v)
			}
			if v, ok := cfg["service"].(string); ok && strings.TrimSpace(v) != "" {
				serviceName = strings.TrimSpace(v)
			}
			if v, ok := cfg["include_options"].(bool); ok {
				includeOptions = v
			}
		}

		return func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if !includeOptions && r.Method == http.MethodOptions {
					next.ServeHTTP(w, r)
					return
				}

				start := time.Now()
				// Attach PrincipalTracker so we can inspect Principal even if authentication
				// runs downstream of audit_log in the middleware chain.
				trackedReq := r.WithContext(middleware.WithPrincipalTracker(r.Context()))
				ww := chimw.NewWrapResponseWriter(w, trackedReq.ProtoMajor)
				next.ServeHTTP(ww, trackedReq)

				status := ww.Status()
				if status == 0 {
					status = http.StatusOK
				}

				userID := ""
				sessionID := ""
				orgID := ""
				tokenID := ""
				kind := ""
				if p, ok := middleware.PrincipalFromContext(trackedReq.Context()); ok && p != nil {
					userID = p.UserID
					sessionID = p.SessionID
					orgID = p.OrgID
					tokenID = p.TokenID
					kind = p.Kind
				}

				// Fallback: extract org_id from Chi route params or URL path `/api/v1/orgs/{org_id}/...`
				// so session-authenticated requests are attributed to the target organization.
				if strings.TrimSpace(orgID) == "" {
					orgID = extractOrgIDFromRequest(trackedReq)
				}

				reqID := middleware.RequestIDFromContext(trackedReq.Context())
				if reqID == "" {
					reqID = strings.TrimSpace(trackedReq.Header.Get("X-Request-ID"))
				}
				clientIP := middleware.ClientIP(trackedReq, deps.TrustedProxies)
				durationMs := time.Since(start).Milliseconds()
				ua := trackedReq.UserAgent()
				routePattern := extractRoutePattern(trackedReq)

				if logger != nil {
					logger.Info("audit_event",
						"method", trackedReq.Method,
						"path", trackedReq.URL.Path,
						"route_pattern", routePattern,
						"status", status,
						"duration_ms", durationMs,
						"request_id", reqID,
						"client_ip", clientIP,
						"user_id", userID,
						"session_id", sessionID,
						"org_id", orgID,
						"token_id", tokenID,
						"principal_kind", kind,
						"user_agent", ua,
					)
				}

				if emitter != nil {
					var orgUUID *uuid.UUID
					if parsed, err := uuid.Parse(strings.TrimSpace(orgID)); err == nil {
						orgUUID = &parsed
					}
					var actorUUID *uuid.UUID
					if parsed, err := uuid.Parse(strings.TrimSpace(userID)); err == nil {
						actorUUID = &parsed
					}
					actorType := pkgAudit.ActorTypeUser
					if kind == middleware.PrincipalKindAPIToken {
						actorType = pkgAudit.ActorTypeAPIToken
					}

					action := customAction
					if action == "" {
						action = pkgAudit.ActionHTTPMethod(trackedReq.Method).String()
					}

					outcome := pkgAudit.StatusSuccess
					if status == http.StatusUnauthorized || status == http.StatusForbidden {
						outcome = pkgAudit.StatusDenied
					} else if status >= 400 {
						outcome = pkgAudit.StatusFailure
					}

					var ipPtr *net.IP
					if parsed := net.ParseIP(strings.TrimSpace(clientIP)); parsed != nil {
						ipPtr = &parsed
					}
					var uaPtr *string
					if trimmedUA := strings.TrimSpace(ua); trimmedUA != "" {
						uaPtr = &trimmedUA
					}

					meta := map[string]any{
						"method":      trackedReq.Method,
						"path":        trackedReq.URL.Path,
						"status":      status,
						"duration_ms": durationMs,
					}
					if routePattern != "" {
						meta["route_pattern"] = routePattern
					}
					if tokenID != "" {
						meta["token_id"] = tokenID
					}
					if sessionID != "" {
						meta["session_id"] = sessionID
					}
					if kind != "" {
						meta["principal_kind"] = kind
					}

					_ = emitter.Emit(trackedReq.Context(), pkgAudit.Event{
						Service:        serviceName,
						Action:         action,
						Status:         outcome,
						OrganizationID: orgUUID,
						Actor: pkgAudit.Actor{
							UserID: actorUUID,
							Type:   actorType,
						},
						Target: pkgAudit.Target{
							Type: customTargetType,
							ID:   trackedReq.URL.Path,
							Name: routePattern,
						},
						ClientContext: pkgAudit.ClientContext{
							IPAddress: ipPtr,
							UserAgent: uaPtr,
							RequestID: reqID,
						},
						Metadata:  meta,
						Timestamp: start.UTC(),
					})
				}
			})
		}, nil
	}
}

func extractOrgIDFromRequest(r *http.Request) string {
	if rctx := chi.RouteContext(r.Context()); rctx != nil {
		if param := strings.TrimSpace(rctx.URLParam("org_id")); param != "" {
			return param
		}
	}
	// Fallback path scan for `/api/v1/orgs/<uuid>`
	const prefix = "/api/v1/orgs/"
	if strings.HasPrefix(r.URL.Path, prefix) {
		rest := strings.TrimPrefix(r.URL.Path, prefix)
		seg, _, _ := strings.Cut(rest, "/")
		if _, err := uuid.Parse(seg); err == nil {
			return seg
		}
	}
	return ""
}

func extractRoutePattern(r *http.Request) string {
	if rctx := chi.RouteContext(r.Context()); rctx != nil {
		return strings.TrimSpace(rctx.RoutePattern())
	}
	return ""
}
