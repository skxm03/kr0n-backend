package gateway

import (
	"log"
	"net/http"
)

// NewRouter constructs an HTTP router with routes and standard middleware.
func NewRouter(h *Handler) http.Handler {
	mux := http.NewServeMux()

	// Register registration endpoint
	mux.HandleFunc("POST /api/v1/auth/register", h.Register)

	// Apply panic recovery middleware
	return recoverMiddleware(mux)
}

func recoverMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				log.Printf("panic recovered in HTTP request [%s %s]: %v", r.Method, r.URL.Path, rec)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusInternalServerError)
				_, _ = w.Write([]byte(`{"error":"internal server error","code":"INTERNAL_SERVER_ERROR"}`))
			}
		}()
		next.ServeHTTP(w, r)
	})
}
