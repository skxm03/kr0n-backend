package builtins

import (
	"github.com/skxm03/kr0n-backend/control-plane/internal/gateway/middleware"
)

// NewRequestIDFactory returns a MiddlewareFactory for chi's RequestID middleware.
func NewRequestIDFactory() middleware.MiddlewareFactory {
	return func(cfg map[string]any) (middleware.Middleware, error) {
		return middleware.RequestID, nil
	}
}

// NewRecoveryFactory returns a MiddlewareFactory for panic recovery.
func NewRecoveryFactory(deps SharedDeps) middleware.MiddlewareFactory {
	return func(cfg map[string]any) (middleware.Middleware, error) {
		return middleware.Recover(deps.Logger), nil
	}
}

// NewAccessLogFactory returns a MiddlewareFactory for structured access logging.
func NewAccessLogFactory(deps SharedDeps) middleware.MiddlewareFactory {
	return func(cfg map[string]any) (middleware.Middleware, error) {
		return middleware.AccessLog(deps.Logger), nil
	}
}
