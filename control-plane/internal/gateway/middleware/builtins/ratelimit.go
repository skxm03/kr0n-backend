package builtins

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/skxm03/kr0n-backend/control-plane/internal/gateway/middleware"
	"github.com/skxm03/kr0n-backend/control-plane/internal/gateway/ratelimit"
)

// In-memory leaky bucket limiter for tests or local dev without Redis
type memoryLimiter struct {
	mu           sync.Mutex
	policy       ratelimit.Policy
	buckets      map[string]*memBucket
	lastEviction time.Time
	maxBuckets   int
	ttl          time.Duration
}

type memBucket struct {
	level      float64
	lastUpdate time.Time
}

func newMemoryLimiter(p ratelimit.Policy) *memoryLimiter {
	leakRate := p.LeakPerSec
	if leakRate <= 0 {
		leakRate = 1.0
	}
	drainSeconds := float64(p.Capacity) / leakRate
	ttl := time.Duration(drainSeconds * float64(time.Second))
	if ttl < 5*time.Second {
		ttl = 5 * time.Second
	}

	return &memoryLimiter{
		policy:       p,
		buckets:      make(map[string]*memBucket),
		lastEviction: time.Now(),
		maxBuckets:   10000,
		ttl:          ttl,
	}
}

// evictExpiredLocked scans and deletes buckets whose level has completely drained to 0.
func (m *memoryLimiter) evictExpiredLocked(now time.Time) {
	for k, b := range m.buckets {
		elapsed := now.Sub(b.lastUpdate).Seconds()
		drainedLevel := b.level - elapsed*m.policy.LeakPerSec
		if drainedLevel <= 0 {
			delete(m.buckets, k)
		}
	}
	// If still above maxBuckets (e.g. flood of unique IPs in short window), prune oldest
	if len(m.buckets) > m.maxBuckets {
		excess := len(m.buckets) - m.maxBuckets
		for k := range m.buckets {
			if excess <= 0 {
				break
			}
			delete(m.buckets, k)
			excess--
		}
	}
	m.lastEviction = now
}

// BucketCount returns the current number of active bucket entries in memory.
func (m *memoryLimiter) BucketCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.buckets)
}

// EvictExpired manually triggers eviction of fully drained buckets up to time `now`.
func (m *memoryLimiter) EvictExpired(now time.Time) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	before := len(m.buckets)
	m.evictExpiredLocked(now)
	return before - len(m.buckets)
}

func (m *memoryLimiter) Allow(ctx context.Context, key string) (ratelimit.Result, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()

	// Periodic eviction check or when max capacity is reached
	if now.Sub(m.lastEviction) >= m.ttl || len(m.buckets) >= m.maxBuckets {
		m.evictExpiredLocked(now)
	}

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
	var (
		memMu       sync.Mutex
		memLimiters = make(map[string]*memoryLimiter)
	)

	return func(cfg map[string]any) (middleware.Middleware, error) {
		capacity := 100
		leakPerSec := 10.0
		keyKind := "ip"
		failOpen := true
		prefix := ""

		if cfg != nil {
			switch reqs := cfg["requests"].(type) {
			case int:
				if reqs > 0 {
					capacity = reqs
				}
			case int64:
				if reqs > 0 {
					capacity = int(reqs)
				}
			case float64:
				if reqs > 0 {
					capacity = int(reqs)
				}
			}
			switch capVal := cfg["capacity"].(type) {
			case int:
				if capVal > 0 {
					capacity = capVal
				}
			case int64:
				if capVal > 0 {
					capacity = int(capVal)
				}
			case float64:
				if capVal > 0 {
					capacity = int(capVal)
				}
			}
			switch rate := cfg["rate_per_sec"].(type) {
			case float64:
				if rate > 0 {
					leakPerSec = rate
				}
			case int:
				if rate > 0 {
					leakPerSec = float64(rate)
				}
			case int64:
				if rate > 0 {
					leakPerSec = float64(rate)
				}
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
			if p, ok := cfg["prefix"].(string); ok && p != "" {
				prefix = p
			} else if z, ok := cfg["zone"].(string); ok && z != "" {
				prefix = "rl:" + z
			} else if n, ok := cfg["name"].(string); ok && n != "" {
				prefix = "rl:" + n
			}
		}

		if prefix == "" {
			prefix = fmt.Sprintf("rl:%d:%d", capacity, int(leakPerSec*1000))
		}

		policy := ratelimit.Policy{
			Capacity:   capacity,
			LeakPerSec: leakPerSec,
		}

		var limiter ratelimit.Limiter
		if deps.LimiterFactory != nil {
			l, err := deps.LimiterFactory(prefix, policy)
			if err != nil {
				return nil, err
			}
			limiter = l
		} else if deps.RedisClient != nil {
			l, err := ratelimit.NewRedis(deps.RedisClient, prefix, policy)
			if err != nil {
				return nil, err
			}
			limiter = l
		} else if deps.Limiter != nil {
			limiter = deps.Limiter
		} else {
			cacheKey := fmt.Sprintf("%s:%d:%.4f", prefix, policy.Capacity, policy.LeakPerSec)
			memMu.Lock()
			l, ok := memLimiters[cacheKey]
			if !ok {
				l = newMemoryLimiter(policy)
				memLimiters[cacheKey] = l
			}
			memMu.Unlock()
			limiter = l
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
