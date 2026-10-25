// Package middleware holds reusable net/http middleware for the API gateway.
package middleware

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/skxm03/kr0n-backend/control-plane/internal/ratelimit"
)

// Middleware wraps an http.Handler.
type Middleware func(http.Handler) http.Handler

// Chain applies middleware so that the first argument is the outermost.
func Chain(h http.Handler, mws ...Middleware) http.Handler {
	for i := len(mws) - 1; i >= 0; i-- {
		h = mws[i](h)
	}
	return h
}

type ctxKey int

const requestIDKey ctxKey = iota

// RequestIDFromContext returns the request ID set by RequestID, or "".
func RequestIDFromContext(ctx context.Context) string {
	id, _ := ctx.Value(requestIDKey).(string)
	return id
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

// RequestID assigns a fresh server-generated ID per request. Client-supplied IDs are ignored
// so they cannot be used for log injection or spoofing.
func RequestID() Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			b := make([]byte, 12)
			_, _ = rand.Read(b)
			id := hex.EncodeToString(b)
			w.Header().Set("X-Request-ID", id)
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), requestIDKey, id)))
		})
	}
}

// Recover converts panics into 500 responses.
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

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (s *statusWriter) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

// AccessLog logs one structured line per request. Query strings are deliberately omitted
// (they may carry OAuth codes or tokens).
func AccessLog(log *slog.Logger) Middleware {
	if log == nil {
		return func(next http.Handler) http.Handler { return next }
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(sw, r)
			log.Info("http request",
				"method", r.Method, "path", r.URL.Path, "status", sw.status,
				"duration_ms", time.Since(start).Milliseconds(),
				"request_id", RequestIDFromContext(r.Context()))
		})
	}
}

// SecureHeaders sets conservative response headers for a JSON API.
func SecureHeaders() Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h := w.Header()
			h.Set("X-Content-Type-Options", "nosniff")
			h.Set("X-Frame-Options", "DENY")
			h.Set("Referrer-Policy", "no-referrer")
			h.Set("Cache-Control", "no-store")
			h.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
			h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
			next.ServeHTTP(w, r)
		})
	}
}

// MaxBody caps request body size.
func MaxBody(n int64) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r.Body = http.MaxBytesReader(w, r.Body, n)
			next.ServeHTTP(w, r)
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
	// Walk right-to-left, returning the first hop that is not one of our proxies.
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

const clientIPKey ctxKey = iota + 200

// ClientIPFromContext returns the IP stored by WithClientIP, or "" if absent.
func ClientIPFromContext(ctx context.Context) string {
	ip, _ := ctx.Value(clientIPKey).(string)
	return ip
}

// WithClientIP resolves the caller IP once (trusted-proxy aware) and stores it in the context,
// so handlers and audit logging all see the same value.
func WithClientIP(trusted []*net.IPNet) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), clientIPKey, ClientIP(r, trusted))))
		})
	}
}
