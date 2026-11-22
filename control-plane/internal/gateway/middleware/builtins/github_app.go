package builtins

import (
	"github.com/skxm03/kr0n-backend/control-plane/internal/gateway/middleware"
	"github.com/skxm03/kr0n-backend/control-plane/internal/gateway/oauth"
)

// NewGitHubAppCallbackFactory creates a middleware that intercepts GitHub App installation
// or setup redirects (which contain "installation_id" or "setup_action" query params)
// and redirects the browser to $FRONTEND_URL/github/callback.
// Non-installation requests (e.g. OAuth code exchange) pass through untouched.
func NewGitHubAppCallbackFactory() middleware.MiddlewareFactory {
	return func(config map[string]any) (middleware.Middleware, error) {
		return oauth.GitHubAppRedirectHandler, nil
	}
}
