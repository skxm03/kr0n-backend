package middleware

import (
	"fmt"
	"net/http"
)

// BuildHandler wraps handler with the given chain in reverse order so that
// chain[0] is the outermost middleware executed first on incoming requests.
func BuildHandler(handler http.Handler, chain []Middleware) http.Handler {
	for i := len(chain) - 1; i >= 0; i-- {
		if chain[i] != nil {
			handler = chain[i](handler)
		}
	}
	return handler
}

// ChainCompiler builds the effective, inherited middleware chain for an endpoint.
type ChainCompiler struct {
	registry *Registry
	resolver *ProfileResolver
}

// NewChainCompiler initializes a ChainCompiler with a frozen registry and profile resolver.
func NewChainCompiler(reg *Registry, resolver *ProfileResolver) *ChainCompiler {
	return &ChainCompiler{
		registry: reg,
		resolver: resolver,
	}
}

// EndpointTarget describes an endpoint being compiled.
type EndpointTarget struct {
	Method     string
	Path       string
	Use        []string
	Middleware []MiddlewareItem
}

// CompileEndpoint resolves the 4-tier hierarchy (Global -> Service -> Group -> Endpoint)
// and returns the final executable http.Handler wrapping baseHandler.
func (c *ChainCompiler) CompileEndpoint(
	baseHandler http.Handler,
	globalItems []MiddlewareItem,
	serviceItems []MiddlewareItem,
	groups []CompiledGroup,
	endpoint EndpointTarget,
) (http.Handler, error) {
	var effectiveItems []MiddlewareItem

	// 1. Global middleware
	effectiveItems = append(effectiveItems, globalItems...)

	// 2. Service middleware
	effectiveItems = append(effectiveItems, serviceItems...)

	// 3. Matching groups (evaluated in configuration declaration order)
	for _, grp := range groups {
		if grp.Matches(endpoint.Method, endpoint.Path) {
			effectiveItems = append(effectiveItems, grp.Middleware...)
		}
	}

	// 4. Endpoint profiles (expanded via resolver)
	if len(endpoint.Use) > 0 && c.resolver != nil {
		profileItems, err := c.resolver.Resolve(endpoint.Use)
		if err != nil {
			return nil, fmt.Errorf("resolve endpoint profiles for %s %s: %w", endpoint.Method, endpoint.Path, err)
		}
		effectiveItems = append(effectiveItems, profileItems...)
	}

	// 5. Endpoint-specific middleware
	effectiveItems = append(effectiveItems, endpoint.Middleware...)

	// 6. Deduplicate idempotent middleware (e.g. duplicate request_id or recovery)
	deduped := deduplicateMiddleware(effectiveItems)

	// 7. Instantiate middleware instances via registry
	var chain []Middleware
	for idx, item := range deduped {
		mw, err := c.registry.Build(item.Name, item.Config)
		if err != nil {
			return nil, fmt.Errorf("build middleware %q at index %d for %s %s: %w", item.Name, idx, endpoint.Method, endpoint.Path, err)
		}
		chain = append(chain, mw)
	}

	// 8. Wrap baseHandler
	return BuildHandler(baseHandler, chain), nil
}

// deduplicateMiddleware preserves order while preventing duplicate stateless wrappers.
func deduplicateMiddleware(items []MiddlewareItem) []MiddlewareItem {
	seenStateless := make(map[string]bool)
	var out []MiddlewareItem

	for _, item := range items {
		// Dedup purely stateless global wrappers if config is empty
		if len(item.Config) == 0 && (item.Name == "request_id" || item.Name == "recovery" || item.Name == "access_log" || item.Name == "authentication" || item.Name == "audit_log") {
			if seenStateless[item.Name] {
				continue
			}
			seenStateless[item.Name] = true
		}
		out = append(out, item)
	}

	return out
}
