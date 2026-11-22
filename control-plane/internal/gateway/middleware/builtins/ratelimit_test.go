package builtins_test

import (
	"context"
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
