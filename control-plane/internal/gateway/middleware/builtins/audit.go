package builtins

import (
	"net"
	"net/http"
	"strings"
	"time"

	chimw "github.com/go-chi/chi/v5/middleware"
	"github.com/google/uuid"

	"github.com/skxm03/kr0n-backend/control-plane/internal/gateway/middleware"
	pkgAudit "github.com/skxm03/kr0n-backend/control-plane/pkg/audit"
)

// NewAuditLogFactory creates a MiddlewareFactory that records security audit logs
// and emits canonical audit events to RabbitMQ when an AuditEmitter is configured.
func NewAuditLogFactory(deps SharedDeps) middleware.MiddlewareFactory {
	return func(cfg map[string]any) (middleware.Middleware, error) {
		logger := deps.Logger
		emitter := deps.AuditEmitter
		if logger == nil && emitter == nil {
			return func(next http.Handler) http.Handler { return next }, nil
		}

		return func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				start := time.Now()
				ww := chimw.NewWrapResponseWriter(w, r.ProtoMajor)
				next.ServeHTTP(ww, r)

				status := ww.Status()
				if status == 0 {
					status = http.StatusOK
				}

				userID := ""
				orgID := ""
				tokenID := ""
				kind := ""
				if p, ok := middleware.PrincipalFromContext(r.Context()); ok {
					userID = p.UserID
					orgID = p.OrgID
					tokenID = p.TokenID
					kind = p.Kind
				}

				reqID := middleware.RequestIDFromContext(r.Context())
				clientIP := middleware.ClientIP(r, deps.TrustedProxies)
				durationMs := time.Since(start).Milliseconds()
				ua := r.UserAgent()

				if logger != nil {
					logger.Info("audit_event",
						"method", r.Method,
						"path", r.URL.Path,
						"status", status,
						"duration_ms", durationMs,
						"request_id", reqID,
						"client_ip", clientIP,
						"user_id", userID,
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

					_ = emitter.Emit(r.Context(), pkgAudit.Event{
						Service:        "gateway",
						Action:         "gateway.http." + strings.ToLower(r.Method),
						Status:         outcome,
						OrganizationID: orgUUID,
						Actor: pkgAudit.Actor{
							UserID: actorUUID,
							Type:   actorType,
						},
						Target: pkgAudit.Target{
							Type: "http_route",
							ID:   r.URL.Path,
						},
						ClientContext: pkgAudit.ClientContext{
							IPAddress: ipPtr,
							UserAgent: uaPtr,
							RequestID: reqID,
						},
						Metadata: map[string]any{
							"method":         r.Method,
							"path":           r.URL.Path,
							"status":         status,
							"duration_ms":    durationMs,
							"token_id":       tokenID,
							"principal_kind": kind,
						},
						Timestamp: start.UTC(),
					})
				}
			})
		}, nil
	}
}
