// Package middleware holds HTTP middleware for the API gateway, built on top of go-chi/chi/v5.
package middleware

import (
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	chimw "github.com/go-chi/chi/v5/middleware"

	"github.com/skxm03/kr0n-backend/control-plane/internal/gateway/ratelimit"
)

// Middleware wraps an http.Handler (compatible with chi's r.Use).
type Middleware = func(http.Handler) http.Handler

type ctxKey int

const clientIPKey ctxKey = iota + 200

// RequestIDFromContext returns the request ID stored by chi's RequestID middleware.
func RequestIDFromContext(ctx context.Context) string {
	return chimw.GetReqID(ctx)
}

// RequestID wraps chi's middleware.RequestID and echoes the generated ID in the X-Request-ID response header.
func RequestID(next http.Handler) http.Handler {
	return chimw.RequestID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Request-ID", chimw.GetReqID(r.Context()))
		next.ServeHTTP(w, r)
	}))
}

// WriteError writes the gateway's uniform JSON error envelope.
func WriteError(w http.ResponseWriter, r *http.Request, status int, message, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":      message,
		"code":       code,
		"request_id": RequestIDFromContext(r.Context()),
	})
}

// Recover converts panics into 500 JSON responses.
func Recover(log *slog.Logger) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if rec := recover(); rec != nil {
					if log != nil {
						log.Error("panic recovered", "method", r.Method, "path", r.URL.Path, "panic", rec, "request_id", RequestIDFromContext(r.Context()))
					}
					WriteError(w, r, http.StatusInternalServerError, "internal server error", "INTERNAL_SERVER_ERROR")
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}

// AccessLog logs one structured line per request using chi's WrapResponseWriter.
func AccessLog(log *slog.Logger) Middleware {
	if log == nil {
		return func(next http.Handler) http.Handler { return next }
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
			log.Info("http request",
				"method", r.Method, "path", r.URL.Path, "status", status,
				"duration_ms", time.Since(start).Milliseconds(),
				"request_id", RequestIDFromContext(r.Context()))
		})
	}
}

// IsTrustedProxy reports whether the direct peer of r is contained in trusted.
func IsTrustedProxy(r *http.Request, trusted []*net.IPNet) bool {
	if len(trusted) == 0 {
		return false
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	peer := net.ParseIP(host)
	if peer == nil {
		return false
	}
	for _, n := range trusted {
		if n.Contains(peer) {
			return true
		}
	}
	return false
}

// ClientIP returns the caller IP. X-Forwarded-For is honored only when the direct peer is in
// trusted (i.e. our own load balancer); otherwise it is attacker-controlled and ignored.
func ClientIP(r *http.Request, trusted []*net.IPNet) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	peer := net.ParseIP(host)
	if peer == nil || len(trusted) == 0 {
		return host
	}
	isTrusted := func(ip net.IP) bool {
		for _, n := range trusted {
			if n.Contains(ip) {
				return true
			}
		}
		return false
	}
	if !isTrusted(peer) {
		return host
	}
	parts := strings.Split(r.Header.Get("X-Forwarded-For"), ",")
	for i := len(parts) - 1; i >= 0; i-- {
		ip := net.ParseIP(strings.TrimSpace(parts[i]))
		if ip == nil {
			continue
		}
		if !isTrusted(ip) {
			return ip.String()
		}
	}
	return host
}

// ClientIPFromContext returns the IP stored by WithClientIP, or "" if absent.
func ClientIPFromContext(ctx context.Context) string {
	ip, _ := ctx.Value(clientIPKey).(string)
	return ip
}

// WithClientIP resolves the caller IP once (trusted-proxy aware) and stores it in the context.
func WithClientIP(trusted []*net.IPNet) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), clientIPKey, ClientIP(r, trusted))))
		})
	}
}

// RateLimit applies limiter per key. When the limiter backend errors, failOpen decides whether
// to admit the request (general routes) or reject it with 503 (credential routes).
func RateLimit(l ratelimit.Limiter, key func(*http.Request) string, failOpen bool, log *slog.Logger) Middleware {
	if l == nil {
		return func(next http.Handler) http.Handler { return next }
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			res, err := l.Allow(r.Context(), key(r))
			if err != nil {
				if log != nil {
					log.Error("rate limiter unavailable", "err", err, "request_id", RequestIDFromContext(r.Context()))
				}
				if failOpen {
					next.ServeHTTP(w, r)
					return
				}
				WriteError(w, r, http.StatusServiceUnavailable, "service temporarily unavailable", "SERVICE_UNAVAILABLE")
				return
			}
			h := w.Header()
			h.Set("RateLimit-Limit", strconv.Itoa(res.Limit))
			h.Set("RateLimit-Remaining", strconv.Itoa(res.Remaining))
			if !res.Allowed {
				secs := int((res.RetryAfter + time.Second - 1) / time.Second)
				if secs < 1 {
					secs = 1
				}
				h.Set("Retry-After", strconv.Itoa(secs))
				WriteError(w, r, http.StatusTooManyRequests, "rate limit exceeded", "RATE_LIMITED")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
