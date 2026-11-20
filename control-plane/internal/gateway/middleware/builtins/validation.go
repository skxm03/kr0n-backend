package builtins

import (
	"context"
	"net/http"
	"strings"
	"time"

	chimw "github.com/go-chi/chi/v5/middleware"

	"github.com/skxm03/kr0n-backend/control-plane/internal/gateway/middleware"
)

// NewRequestValidationFactory creates a MiddlewareFactory for validating payload Content-Type and size.
func NewRequestValidationFactory(deps SharedDeps) middleware.MiddlewareFactory {
	return func(cfg map[string]any) (middleware.Middleware, error) {
		enforceJSON := true
		maxBodyBytes := deps.MaxBodyBytes
		if maxBodyBytes <= 0 {
			maxBodyBytes = 1 << 20 // 1 MB default
		}

		if cfg != nil {
			if ej, ok := cfg["enforce_json"].(bool); ok {
				enforceJSON = ej
			}
			if mb, ok := cfg["max_body_bytes"].(int); ok && mb > 0 {
				maxBodyBytes = int64(mb)
			}
			if mb, ok := cfg["max_body_bytes"].(int64); ok && mb > 0 {
				maxBodyBytes = mb
			}
		}

		sizeMW := chimw.RequestSize(maxBodyBytes)

		return func(next http.Handler) http.Handler {
			handler := next
			if enforceJSON {
				handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodPatch {
						if r.ContentLength > 0 || r.Header.Get("Transfer-Encoding") != "" {
							ct := r.Header.Get("Content-Type")
							if !strings.HasPrefix(strings.ToLower(ct), "application/json") {
								middleware.WriteError(w, r, http.StatusUnsupportedMediaType, "content-type must be application/json", "UNSUPPORTED_MEDIA_TYPE")
								return
							}
						}
					}
					next.ServeHTTP(w, r)
				})
			}
			return sizeMW(handler)
		}, nil
	}
}

// NewTimeoutFactory creates a MiddlewareFactory that enforces a request context deadline.
func NewTimeoutFactory() middleware.MiddlewareFactory {
	return func(cfg map[string]any) (middleware.Middleware, error) {
		timeout := 10 * time.Second
		if cfg != nil {
			if dStr, ok := cfg["duration"].(string); ok && dStr != "" {
				if d, err := time.ParseDuration(dStr); err == nil && d > 0 {
					timeout = d
				}
			}
			if sec, ok := cfg["seconds"].(int); ok && sec > 0 {
				timeout = time.Duration(sec) * time.Second
			}
		}

		return func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				ctx, cancel := context.WithTimeout(r.Context(), timeout)
				defer cancel()
				next.ServeHTTP(w, r.WithContext(ctx))
			})
		}, nil
	}
}
