package builtins

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/skxm03/kr0n-backend/control-plane/internal/gateway/middleware"
)

// NewCORSFactory creates a MiddlewareFactory for Cross-Origin Resource Sharing.
func NewCORSFactory() middleware.MiddlewareFactory {
	return func(cfg map[string]any) (middleware.Middleware, error) {
		allowedOrigins := []string{"*"}
		allowedMethods := []string{"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}
		allowedHeaders := []string{"Authorization", "Content-Type", "X-Request-ID"}
		exposedHeaders := []string{"X-Request-ID", "RateLimit-Limit", "RateLimit-Remaining", "Retry-After"}
		allowCredentials := false
		maxAgeSec := 86400

		if cfg != nil {
			if origins, ok := cfg["allowed_origins"].([]any); ok {
				allowedOrigins = nil
				for _, o := range origins {
					if s, ok := o.(string); ok {
						allowedOrigins = append(allowedOrigins, strings.TrimSpace(s))
					}
				}
			}
			if methods, ok := cfg["allowed_methods"].([]any); ok {
				allowedMethods = nil
				for _, m := range methods {
					if s, ok := m.(string); ok {
						allowedMethods = append(allowedMethods, strings.ToUpper(strings.TrimSpace(s)))
					}
				}
			}
			if headers, ok := cfg["allowed_headers"].([]any); ok {
				allowedHeaders = nil
				for _, h := range headers {
					if s, ok := h.(string); ok {
						allowedHeaders = append(allowedHeaders, strings.TrimSpace(s))
					}
				}
			}
			if creds, ok := cfg["allow_credentials"].(bool); ok {
				allowCredentials = creds
			}
			if age, ok := cfg["max_age"].(int); ok && age > 0 {
				maxAgeSec = age
			}
		}

		methodsStr := strings.Join(allowedMethods, ", ")
		headersStr := strings.Join(allowedHeaders, ", ")
		exposedStr := strings.Join(exposedHeaders, ", ")
		maxAgeStr := strconv.Itoa(maxAgeSec)
		allowAllOrigins := len(allowedOrigins) == 1 && allowedOrigins[0] == "*"

		originsMap := make(map[string]bool)
		for _, o := range allowedOrigins {
			originsMap[strings.ToLower(o)] = true
		}

		return func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				origin := r.Header.Get("Origin")
				if origin == "" {
					next.ServeHTTP(w, r)
					return
				}

				matchedOrigin := ""
				if allowAllOrigins {
					matchedOrigin = "*"
					if allowCredentials {
						matchedOrigin = origin
					}
				} else if originsMap[strings.ToLower(origin)] {
					matchedOrigin = origin
				}

				if matchedOrigin != "" {
					w.Header().Set("Access-Control-Allow-Origin", matchedOrigin)
					w.Header().Set("Vary", "Origin")
					if allowCredentials {
						w.Header().Set("Access-Control-Allow-Credentials", "true")
					}
					if len(exposedHeaders) > 0 {
						w.Header().Set("Access-Control-Expose-Headers", exposedStr)
					}
				}

				if r.Method == http.MethodOptions {
					if matchedOrigin != "" {
						w.Header().Set("Access-Control-Allow-Methods", methodsStr)
						w.Header().Set("Access-Control-Allow-Headers", headersStr)
						w.Header().Set("Access-Control-Max-Age", maxAgeStr)
					}
					w.WriteHeader(http.StatusNoContent)
					return
				}

				next.ServeHTTP(w, r)
			})
		}, nil
	}
}
