package builtins

import (
	"fmt"

	"github.com/skxm03/kr0n-backend/control-plane/internal/gateway/middleware"
)

// RegisterDefaults registers the 9 standard gateway middleware factories into reg.
func RegisterDefaults(reg *middleware.Registry, deps SharedDeps) error {
	if reg == nil {
		return fmt.Errorf("registry cannot be nil")
	}

	factories := map[string]middleware.MiddlewareFactory{
		"request_id":         NewRequestIDFactory(),
		"recovery":           NewRecoveryFactory(deps),
		"access_log":         NewAccessLogFactory(deps),
		"cors":               NewCORSFactory(),
		"authentication":     NewAuthenticationFactory(deps),
		"rate_limit":         NewRateLimitFactory(deps),
		"audit_log":          NewAuditLogFactory(deps),
		"request_validation": NewRequestValidationFactory(deps),
		"timeout":            NewTimeoutFactory(),
		"github_app_callback": NewGitHubAppCallbackFactory(),
	}

	for name, factory := range factories {
		if err := reg.Register(name, factory); err != nil {
			return fmt.Errorf("register builtin middleware %q: %w", name, err)
		}
	}

	return nil
}
