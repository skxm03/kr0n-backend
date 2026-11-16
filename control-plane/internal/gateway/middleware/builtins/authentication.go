package builtins

import (
	"net/http"
	"strings"

	"github.com/skxm03/kr0n-backend/control-plane/internal/gateway/middleware"
)

// NewAuthenticationFactory creates a MiddlewareFactory for JWT and API token authentication.
func NewAuthenticationFactory(deps SharedDeps) middleware.MiddlewareFactory {
	return func(cfg map[string]any) (middleware.Middleware, error) {
		allowAPITokens := true
		required := true
		var requirePermissions []string

		if cfg != nil {
			if allow, ok := cfg["allow_api_tokens"].(bool); ok {
				allowAPITokens = allow
			}
			if req, ok := cfg["required"].(bool); ok {
				required = req
			}
			if perms, ok := cfg["require_permissions"].([]any); ok {
				for _, p := range perms {
					if s, ok := p.(string); ok && s != "" {
						requirePermissions = append(requirePermissions, strings.TrimSpace(s))
					}
				}
			}
		}

		if !required {
			// Optional authentication / no-op if explicitly disabled
			return func(next http.Handler) http.Handler { return next }, nil
		}

		authMW := middleware.Authenticate(deps.Verifier, deps.APITokenVerifier)

		return func(next http.Handler) http.Handler {
			handler := next
			if len(requirePermissions) > 0 {
				handler = middleware.RequirePermission(requirePermissions...)(handler)
			}
			if !allowAPITokens {
				handler = middleware.RejectAPIToken()(handler)
			}
			return authMW(handler)
		}, nil
	}
}
