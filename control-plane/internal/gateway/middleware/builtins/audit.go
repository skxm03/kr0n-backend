package builtins

import (
	"net/http"
	"time"

	chimw "github.com/go-chi/chi/v5/middleware"

	"github.com/skxm03/kr0n-backend/control-plane/internal/gateway/middleware"
)

// NewAuditLogFactory creates a MiddlewareFactory that records security audit logs.
func NewAuditLogFactory(deps SharedDeps) middleware.MiddlewareFactory {
	return func(cfg map[string]any) (middleware.Middleware, error) {
		logger := deps.Logger
		if logger == nil {
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

				logger.Info("audit_event",
					"method", r.Method,
					"path", r.URL.Path,
					"status", status,
					"duration_ms", time.Since(start).Milliseconds(),
					"request_id", middleware.RequestIDFromContext(r.Context()),
					"client_ip", middleware.ClientIP(r, deps.TrustedProxies),
					"user_id", userID,
					"org_id", orgID,
					"token_id", tokenID,
					"principal_kind", kind,
					"user_agent", r.UserAgent(),
				)
			})
		}, nil
	}
}
