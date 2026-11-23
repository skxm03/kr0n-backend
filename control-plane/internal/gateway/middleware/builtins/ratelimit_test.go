package builtins_test

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"

	"github.com/skxm03/kr0n-backend/control-plane/internal/gateway/middleware"
	"github.com/skxm03/kr0n-backend/control-plane/internal/gateway/middleware/builtins"
)

func TestRateLimitFactory_RouteSpecificPoliciesWithRedis(t *testing.T) {
	mr := miniredis.RunT(t)
	mr.SetTime(time.Unix(1_700_000_000, 0))
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })

	deps := builtins.SharedDeps{
		RedisClient: rdb,
	}
	factory := builtins.NewRateLimitFactory(deps)

	// Create a public limiter (capacity 3)
	publicMw, err := factory(map[string]any{
		"requests": 3,
		"window":   "1m",
		"zone":     "public",
		"key":      "ip",
	})
	if err != nil {
		t.Fatalf("failed to create public rate limit mw: %v", err)
	}

	// Create a sensitive limiter (capacity 1)
	sensitiveMw, err := factory(map[string]any{
		"requests": 1,
		"window":   "1m",
		"zone":     "sensitive",
		"key":      "ip",
	})
	if err != nil {
		t.Fatalf("failed to create sensitive rate limit mw: %v", err)
	}

	okHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	publicH := publicMw(okHandler)
	sensitiveH := sensitiveMw(okHandler)

	// 1. Consume all 3 public tokens
	for i := 0; i < 3; i++ {
		req := httptest.NewRequest("GET", "/api/v1/public", nil)
		req.RemoteAddr = "192.168.1.1:1234"
		rec := httptest.NewRecorder()
		publicH.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("public req %d expected 200, got %d", i, rec.Code)
		}
		if rec.Header().Get("RateLimit-Limit") != "3" {
			t.Fatalf("expected RateLimit-Limit 3, got %s", rec.Header().Get("RateLimit-Limit"))
		}
	}

	// 4th public req should be 429
	reqPublic4 := httptest.NewRequest("GET", "/api/v1/public", nil)
	reqPublic4.RemoteAddr = "192.168.1.1:1234"
	recPublic4 := httptest.NewRecorder()
	publicH.ServeHTTP(recPublic4, reqPublic4)
	if recPublic4.Code != http.StatusTooManyRequests {
		t.Fatalf("4th public req expected 429, got %d", recPublic4.Code)
	}

	// 2. Sensitive endpoint should still be available (isolated zone)
	reqSens1 := httptest.NewRequest("POST", "/api/v1/orgs", nil)
	reqSens1.RemoteAddr = "192.168.1.1:1234"
	recSens1 := httptest.NewRecorder()
	sensitiveH.ServeHTTP(recSens1, reqSens1)

	if recSens1.Code != http.StatusOK {
		t.Fatalf("sensitive req 1 expected 200, got %d", recSens1.Code)
	}
	if recSens1.Header().Get("RateLimit-Limit") != "1" {
		t.Fatalf("expected RateLimit-Limit 1, got %s", recSens1.Header().Get("RateLimit-Limit"))
	}

	// 2nd sensitive req should be 429
	reqSens2 := httptest.NewRequest("POST", "/api/v1/orgs", nil)
	reqSens2.RemoteAddr = "192.168.1.1:1234"
	recSens2 := httptest.NewRecorder()
	sensitiveH.ServeHTTP(recSens2, reqSens2)
	if recSens2.Code != http.StatusTooManyRequests {
		t.Fatalf("2nd sensitive req expected 429, got %d", recSens2.Code)
	}
}

func TestRateLimitFactory_PrincipalKeying(t *testing.T) {
	mr := miniredis.RunT(t)
	mr.SetTime(time.Unix(1_700_000_000, 0))
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })

	deps := builtins.SharedDeps{
		RedisClient: rdb,
	}
	factory := builtins.NewRateLimitFactory(deps)

	userMw, err := factory(map[string]any{
		"requests": 1,
		"window":   "1m",
		"zone":     "user-zone",
		"key":      "user",
	})
	if err != nil {
		t.Fatalf("failed to create user rate limit mw: %v", err)
	}

	h := userMw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// User A request from IP 1.2.3.4
	ctxA := middleware.WithPrincipal(context.Background(), &middleware.Principal{UserID: "user-A"})
	reqA1 := httptest.NewRequest("GET", "/test", nil).WithContext(ctxA)
	reqA1.RemoteAddr = "1.2.3.4:1234"
	recA1 := httptest.NewRecorder()
	h.ServeHTTP(recA1, reqA1)
	if recA1.Code != http.StatusOK {
		t.Fatalf("expected 200 for user A, got %d", recA1.Code)
	}

	// User A second request -> 429
	reqA2 := httptest.NewRequest("GET", "/test", nil).WithContext(ctxA)
	reqA2.RemoteAddr = "1.2.3.4:1234"
	recA2 := httptest.NewRecorder()
	h.ServeHTTP(recA2, reqA2)
	if recA2.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 for user A 2nd request, got %d", recA2.Code)
	}

	// User B request from same IP 1.2.3.4 -> should succeed because keyed by user
	ctxB := middleware.WithPrincipal(context.Background(), &middleware.Principal{UserID: "user-B"})
	reqB1 := httptest.NewRequest("GET", "/test", nil).WithContext(ctxB)
	reqB1.RemoteAddr = "1.2.3.4:1234"
	recB1 := httptest.NewRecorder()
	h.ServeHTTP(recB1, reqB1)
	if recB1.Code != http.StatusOK {
		t.Fatalf("expected 200 for user B from same IP, got %d", recB1.Code)
	}
}

func TestRateLimitFactory_FailOpenConfig(t *testing.T) {
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	mr.Close() // Force immediate connection failure

	deps := builtins.SharedDeps{
		RedisClient: rdb,
	}
	factory := builtins.NewRateLimitFactory(deps)

	// Fail closed (sensitive)
	failClosedMw, err := factory(map[string]any{
		"requests":  10,
		"window":    "1m",
		"fail_open": false,
	})
	if err != nil {
		t.Fatalf("create mw err: %v", err)
	}

	// Fail open (public)
	failOpenMw, err := factory(map[string]any{
		"requests":  10,
		"window":    "1m",
		"fail_open": true,
	})
	if err != nil {
		t.Fatalf("create mw err: %v", err)
	}

	dummyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Fail closed returns 503
	req1 := httptest.NewRequest("GET", "/sensitive", nil)
	rec1 := httptest.NewRecorder()
	failClosedMw(dummyHandler).ServeHTTP(rec1, req1)
	if rec1.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 on fail closed, got %d", rec1.Code)
	}

	// Fail open passes through with 200
	req2 := httptest.NewRequest("GET", "/public", nil)
	rec2 := httptest.NewRecorder()
	failOpenMw(dummyHandler).ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusOK {
		t.Fatalf("expected 200 on fail open, got %d", rec2.Code)
	}
}

func TestRateLimit_BlastRadiusIsolation_NoUserMetadata(t *testing.T) {
	mr := miniredis.RunT(t)
	mr.SetTime(time.Unix(1_700_000_000, 0))
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })

	deps := builtins.SharedDeps{RedisClient: rdb}
	factory := builtins.NewRateLimitFactory(deps)

	// Route A: Public Docs/Search (zone: "public", capacity: 2)
	routeAMw, err := factory(map[string]any{
		"requests": 2,
		"window":   "1m",
		"zone":     "public-docs",
		"key":      "ip",
	})
	if err != nil {
		t.Fatalf("create route A mw: %v", err)
	}

	// Route B: Login / Register (zone: "public-auth", capacity: 5)
	routeBMw, err := factory(map[string]any{
		"requests": 5,
		"window":   "1m",
		"zone":     "public-auth",
		"key":      "ip",
	})
	if err != nil {
		t.Fatalf("create route B mw: %v", err)
	}

	dummyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	handlerA := routeAMw(dummyHandler)
	handlerB := routeBMw(dummyHandler)

	clientIP := "203.0.113.50:4321"

	// 1. Exhaust Route A with 2 requests from clientIP (NO user metadata)
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest("GET", "/api/v1/docs", nil)
		req.RemoteAddr = clientIP
		rec := httptest.NewRecorder()
		handlerA.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("route A req %d expected 200, got %d", i, rec.Code)
		}
	}

	// 3rd request to Route A must be 429 Too Many Requests
	reqA3 := httptest.NewRequest("GET", "/api/v1/docs", nil)
	reqA3.RemoteAddr = clientIP
	recA3 := httptest.NewRecorder()
	handlerA.ServeHTTP(recA3, reqA3)
	if recA3.Code != http.StatusTooManyRequests {
		t.Fatalf("route A 3rd request expected 429, got %d", recA3.Code)
	}

	// 2. Blast-Radius Check: The EXACT SAME IP with NO user metadata hits Route B (/api/v1/auth/login)
	// It MUST succeed with 200 OK because Route B uses an isolated zone ("public-auth") in Redis!
	for i := 0; i < 5; i++ {
		reqB := httptest.NewRequest("POST", "/api/v1/auth/login", nil)
		reqB.RemoteAddr = clientIP
		recB := httptest.NewRecorder()
		handlerB.ServeHTTP(recB, reqB)
		if recB.Code != http.StatusOK {
			t.Fatalf("route B req %d from exhausted IP expected 200, got %d", i, recB.Code)
		}
	}

	// 6th request to Route B is now 429
	reqB6 := httptest.NewRequest("POST", "/api/v1/auth/login", nil)
	reqB6.RemoteAddr = clientIP
	recB6 := httptest.NewRecorder()
	handlerB.ServeHTTP(recB6, reqB6)
	if recB6.Code != http.StatusTooManyRequests {
		t.Fatalf("route B 6th request expected 429, got %d", recB6.Code)
	}
}

func TestRateLimit_SpoofedXForwardedForIgnored_UnlessTrusted(t *testing.T) {
	mr := miniredis.RunT(t)
	mr.SetTime(time.Unix(1_700_000_000, 0))
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })

	_, trustedCIDR, _ := net.ParseCIDR("10.0.0.0/8")
	deps := builtins.SharedDeps{
		RedisClient:    rdb,
		TrustedProxies: []*net.IPNet{trustedCIDR},
	}
	factory := builtins.NewRateLimitFactory(deps)

	mw, err := factory(map[string]any{
		"requests": 1,
		"window":   "1m",
		"zone":     "ip-spoof-test",
		"key":      "ip",
	})
	if err != nil {
		t.Fatalf("create mw: %v", err)
	}

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Case 1: Untrusted attacker at 198.51.100.7 sends spoofed "X-Forwarded-For: 8.8.8.8"
	req1 := httptest.NewRequest("GET", "/test", nil)
	req1.RemoteAddr = "198.51.100.7:1234"
	req1.Header.Set("X-Forwarded-For", "8.8.8.8")
	rec1 := httptest.NewRecorder()
	handler.ServeHTTP(rec1, req1)
	if rec1.Code != http.StatusOK {
		t.Fatalf("req 1 expected 200, got %d", rec1.Code)
	}

	// Attacker changes spoofed header to "X-Forwarded-For: 9.9.9.9" from same real IP 198.51.100.7
	// Must be REJECTED with 429 because untrusted X-Forwarded-For is ignored!
	req2 := httptest.NewRequest("GET", "/test", nil)
	req2.RemoteAddr = "198.51.100.7:1234"
	req2.Header.Set("X-Forwarded-For", "9.9.9.9")
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusTooManyRequests {
		t.Fatalf("attacker bypassed rate limiter via spoofed X-Forwarded-For! got %d, want 429", rec2.Code)
	}

	// Case 2: Trusted Proxy (10.0.0.1) forwarding legitimate client IP (203.0.113.195)
	reqTrusted1 := httptest.NewRequest("GET", "/test", nil)
	reqTrusted1.RemoteAddr = "10.0.0.1:5555"
	reqTrusted1.Header.Set("X-Forwarded-For", "203.0.113.195")
	recTrusted1 := httptest.NewRecorder()
	handler.ServeHTTP(recTrusted1, reqTrusted1)
	if recTrusted1.Code != http.StatusOK {
		t.Fatalf("trusted proxy req 1 expected 200, got %d", recTrusted1.Code)
	}

	// Second request from same legitimate client 203.0.113.195 through trusted proxy -> 429
	reqTrusted2 := httptest.NewRequest("GET", "/test", nil)
	reqTrusted2.RemoteAddr = "10.0.0.1:5555"
	reqTrusted2.Header.Set("X-Forwarded-For", "203.0.113.195")
	recTrusted2 := httptest.NewRecorder()
	handler.ServeHTTP(recTrusted2, reqTrusted2)
	if recTrusted2.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 for second request from 203.0.113.195, got %d", recTrusted2.Code)
	}
}

func TestRateLimit_LeakyBucketDrainsAndRecovers(t *testing.T) {
	mr := miniredis.RunT(t)
	mr.SetTime(time.Unix(1_700_000_000, 0))
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })

	deps := builtins.SharedDeps{RedisClient: rdb}
	factory := builtins.NewRateLimitFactory(deps)

	// Capacity: 2, drains at 1 request per second
	mw, err := factory(map[string]any{
		"capacity":     2,
		"rate_per_sec": 1.0,
		"zone":         "drain-test",
		"key":          "ip",
	})
	if err != nil {
		t.Fatalf("create mw: %v", err)
	}

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	clientIP := "192.168.1.100:1234"

	// 1. Consume 2 tokens
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest("GET", "/test", nil)
		req.RemoteAddr = clientIP
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("req %d expected 200, got %d", i, rec.Code)
		}
	}

	// 2. 3rd request is blocked (429)
	req3 := httptest.NewRequest("GET", "/test", nil)
	req3.RemoteAddr = clientIP
	rec3 := httptest.NewRecorder()
	handler.ServeHTTP(rec3, req3)
	if rec3.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 when bucket full, got %d", rec3.Code)
	}

	// 3. Fast-forward time by 1.1 seconds in Redis (leaks 1 slot)
	mr.SetTime(time.Unix(1_700_000_001, 100_000_000))

	// Now 1 request must be permitted!
	req4 := httptest.NewRequest("GET", "/test", nil)
	req4.RemoteAddr = clientIP
	rec4 := httptest.NewRecorder()
	handler.ServeHTTP(rec4, req4)
	if rec4.Code != http.StatusOK {
		t.Fatalf("expected 200 after 1s bucket drain, got %d", rec4.Code)
	}

	// But immediate next request fills the drained slot and is 429
	req5 := httptest.NewRequest("GET", "/test", nil)
	req5.RemoteAddr = clientIP
	rec5 := httptest.NewRecorder()
	handler.ServeHTTP(rec5, req5)
	if rec5.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 after refilling slot, got %d", rec5.Code)
	}
}

func TestRateLimit_MemoryLimiter_EvictsDrainedBuckets(t *testing.T) {
	// In-memory limiter with capacity 2 and high leak rate (drain in ~100ms)
	factory := builtins.NewRateLimitFactory(builtins.SharedDeps{})

	mw, err := factory(map[string]any{
		"capacity":     2,
		"rate_per_sec": 20.0, // Drains in 100ms
		"zone":         "mem_evict_test",
		"key":          "ip",
	})
	if err != nil {
		t.Fatalf("create memory mw: %v", err)
	}

	okHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	h := mw(okHandler)

	// Send requests across 20 distinct IPs
	for i := 1; i <= 20; i++ {
		req := httptest.NewRequest("GET", "/test", nil)
		req.RemoteAddr = net.JoinHostPort(net.IPv4(10, 0, 0, byte(i)).String(), "12345")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200 for ip %d, got %d", i, rec.Code)
		}
	}

	// Wait for buckets to fully drain (150ms > 100ms)
	time.Sleep(150 * time.Millisecond)

	// Next request triggers lazy sweep
	req21 := httptest.NewRequest("GET", "/test", nil)
	req21.RemoteAddr = "10.0.1.1:12345"
	rec21 := httptest.NewRecorder()
	h.ServeHTTP(rec21, req21)
	if rec21.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec21.Code)
	}
}

func TestRateLimit_TwoTierDefense_UnauthenticatedBlockedAtPerimeter(t *testing.T) {
	// Outer IP rate limiter (capacity 2) -> Authentication -> Inner user rate limiter (capacity 10)
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })

	deps := builtins.SharedDeps{RedisClient: rdb}
	factory := builtins.NewRateLimitFactory(deps)

	outerIPMw, err := factory(map[string]any{
		"requests": 2,
		"window":   "1m",
		"zone":     "perimeter_ip",
		"key":      "ip",
	})
	if err != nil {
		t.Fatalf("create outer limiter: %v", err)
	}

	innerUserMw, err := factory(map[string]any{
		"requests": 10,
		"window":   "1m",
		"zone":     "inner_user",
		"key":      "user",
	})
	if err != nil {
		t.Fatalf("create inner limiter: %v", err)
	}

	authCallCount := 0
	authMw := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authCallCount++
			p, ok := middleware.PrincipalFromContext(r.Context())
			if !ok || p == nil || p.UserID == "" {
				http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, r)
		})
	}

	endpoint := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Pipeline: Outer IP Limiter -> Auth -> Inner User Limiter -> Endpoint
	chain := middleware.BuildHandler(endpoint, []middleware.Middleware{
		outerIPMw,
		authMw,
		innerUserMw,
	})

	clientIP := "198.51.100.55:54321"

	// 1. First unauthenticated request passes outer IP limiter, but fails at auth (401)
	req1 := httptest.NewRequest("GET", "/api/v1/protected", nil)
	req1.RemoteAddr = clientIP
	rec1 := httptest.NewRecorder()
	chain.ServeHTTP(rec1, req1)
	if rec1.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec1.Code)
	}

	// 2. Second unauthenticated request passes outer IP limiter, fails at auth (401)
	req2 := httptest.NewRequest("GET", "/api/v1/protected", nil)
	req2.RemoteAddr = clientIP
	rec2 := httptest.NewRecorder()
	chain.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec2.Code)
	}
	if authCallCount != 2 {
		t.Fatalf("expected auth called twice, got %d", authCallCount)
	}

	// 3. Third unauthenticated request exceeds outer IP limit (capacity 2 exhausted)
	// IT MUST BE BLOCKED BY 429 TOO MANY REQUESTS BEFORE EVEN REACHING AUTH!
	req3 := httptest.NewRequest("GET", "/api/v1/protected", nil)
	req3.RemoteAddr = clientIP
	rec3 := httptest.NewRecorder()
	chain.ServeHTTP(rec3, req3)
	if rec3.Code != http.StatusTooManyRequests {
		t.Fatalf("security violation: expected 429 Too Many Requests from outer IP limiter, got %d", rec3.Code)
	}
	// Auth must NOT have been called for the 3rd request!
	if authCallCount != 2 {
		t.Fatalf("auth should not be invoked when throttled at perimeter, expected 2 calls, got %d", authCallCount)
	}
}

func TestRateLimitFactory_IntegerRatePerSec(t *testing.T) {
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })

	deps := builtins.SharedDeps{
		RedisClient: rdb,
	}
	factory := builtins.NewRateLimitFactory(deps)

	// Configure with integer rate_per_sec and integer capacity
	mw, err := factory(map[string]any{
		"capacity":     5,
		"rate_per_sec": 2, // integer instead of float64
		"zone":         "integer_test",
	})
	if err != nil {
		t.Fatalf("failed to create rate limit mw with integer rate_per_sec: %v", err)
	}
	if mw == nil {
		t.Fatal("expected non-nil middleware")
	}
}
