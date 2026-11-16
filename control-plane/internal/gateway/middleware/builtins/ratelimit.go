package builtins

import (
	"context"
	"net/http"
	"sync"
	"time"

	"github.com/skxm03/kr0n-backend/control-plane/internal/gateway/middleware"
	"github.com/skxm03/kr0n-backend/control-plane/internal/gateway/ratelimit"
)

// In-memory leaky bucket limiter for tests or local dev without Redis
type memoryLimiter struct {
	mu      sync.Mutex
	policy  ratelimit.Policy
	buckets map[string]*memBucket
}

type memBucket struct {
	level      float64
	lastUpdate time.Time
}

func newMemoryLimiter(p ratelimit.Policy) *memoryLimiter {
	return &memoryLimiter{
		policy:  p,
		buckets: make(map[string]*memBucket),
	}
}

func (m *memoryLimiter) Allow(ctx context.Context, key string) (ratelimit.Result, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	b, ok := m.buckets[key]
	if !ok {
		b = &memBucket{level: 0, lastUpdate: now}
		m.buckets[key] = b
	}

	// Drain
	elapsed := now.Sub(b.lastUpdate).Seconds()
	b.level = b.level - elapsed*m.policy.LeakPerSec
	if b.level < 0 {
		b.level = 0
	}
	b.lastUpdate = now

	if b.level+1 > float64(m.policy.Capacity) {
		overflow := (b.level + 1) - float64(m.policy.Capacity)
		retryAfter := time.Duration((overflow / m.policy.LeakPerSec) * float64(time.Second))
		return ratelimit.Result{
			Allowed:    false,
			Limit:      m.policy.Capacity,
			Remaining:  0,
			RetryAfter: retryAfter,
		}, nil
	}

	b.level += 1
	remaining := m.policy.Capacity - int(b.level)
	if remaining < 0 {
		remaining = 0
	}

	return ratelimit.Result{
		Allowed:   true,
		Limit:     m.policy.Capacity,
		Remaining: remaining,
	}, nil
}

// NewRateLimitFactory creates a MiddlewareFactory for rate limiting.
func NewRateLimitFactory(deps SharedDeps) middleware.MiddlewareFactory {
	return func(cfg map[string]any) (middleware.Middleware, error) {
		capacity := 100
		leakPerSec := 10.0
		keyKind := "ip"
		failOpen := true

		if cfg != nil {
			if reqs, ok := cfg["requests"].(int); ok && reqs > 0 {
				capacity = reqs
			}
			if capVal, ok := cfg["capacity"].(int); ok && capVal > 0 {
				capacity = capVal
			}
			if rate, ok := cfg["rate_per_sec"].(float64); ok && rate > 0 {
				leakPerSec = rate
			}
			if winStr, ok := cfg["window"].(string); ok && winStr != "" {
				d, err := time.ParseDuration(winStr)
				if err == nil && d.Seconds() > 0 {
					leakPerSec = float64(capacity) / d.Seconds()
				}
			}
			if k, ok := cfg["key"].(string); ok && k != "" {
				keyKind = k
			}
			if fo, ok := cfg["fail_open"].(bool); ok {
				failOpen = fo
			}
		}

		policy := ratelimit.Policy{
			Capacity:   capacity,
			LeakPerSec: leakPerSec,
		}

		limiter := deps.Limiter
		if limiter == nil {
			limiter = newMemoryLimiter(policy)
		}

		keyFunc := func(r *http.Request) string {
			switch keyKind {
			case "user":
				if p, ok := middleware.PrincipalFromContext(r.Context()); ok && p.UserID != "" {
					return "user:" + p.UserID
				}
				return "ip:" + middleware.ClientIP(r, deps.TrustedProxies)
			case "token":
				if p, ok := middleware.PrincipalFromContext(r.Context()); ok && p.TokenID != "" {
					return "token:" + p.TokenID
				}
				return "ip:" + middleware.ClientIP(r, deps.TrustedProxies)
			default:
				return "ip:" + middleware.ClientIP(r, deps.TrustedProxies)
			}
		}

		return middleware.RateLimit(limiter, keyFunc, failOpen, deps.Logger), nil
	}
}
