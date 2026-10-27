package ratelimit

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"

	"github.com/skxm03/kr0n-backend/control-plane/internal/testdb"
)

func newTestLimiter(t *testing.T, p Policy) (*Redis, *miniredis.Miniredis) {
	t.Helper()
	mr := miniredis.RunT(t)
	mr.SetTime(time.Unix(1_700_000_000, 0))
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	l, err := NewRedis(client, "rl", p)
	if err != nil {
		t.Fatal(err)
	}
	return l, mr
}

func TestLeakyBucketBurstThenReject(t *testing.T) {
	l, _ := newTestLimiter(t, Policy{Capacity: 3, LeakPerSec: 1})
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		r, err := l.Allow(ctx, "ip1")
		if err != nil || !r.Allowed {
			t.Fatalf("request %d: allowed=%v err=%v", i, r.Allowed, err)
		}
	}
	r, err := l.Allow(ctx, "ip1")
	if err != nil {
		t.Fatal(err)
	}
	if r.Allowed {
		t.Fatal("4th request should be rejected")
	}
	if r.RetryAfter <= 0 || r.RetryAfter > time.Second {
		t.Fatalf("RetryAfter = %v, want (0, 1s]", r.RetryAfter)
	}
}

func TestLeakyBucketDrainsOverTime(t *testing.T) {
	l, mr := newTestLimiter(t, Policy{Capacity: 2, LeakPerSec: 1})
	ctx := context.Background()

	l.Allow(ctx, "k")
	l.Allow(ctx, "k")
	if r, _ := l.Allow(ctx, "k"); r.Allowed {
		t.Fatal("bucket should be full")
	}

	mr.SetTime(time.Unix(1_700_000_001, 0)) // one second leaks exactly one slot
	if r, _ := l.Allow(ctx, "k"); !r.Allowed {
		t.Fatal("expected one slot to have drained")
	}
	if r, _ := l.Allow(ctx, "k"); r.Allowed {
		t.Fatal("only one slot should have drained")
	}
}

func TestLeakyBucketKeysAreIsolated(t *testing.T) {
	l, _ := newTestLimiter(t, Policy{Capacity: 1, LeakPerSec: 0.1})
	ctx := context.Background()

	if r, _ := l.Allow(ctx, "a"); !r.Allowed {
		t.Fatal("a first request should pass")
	}
	if r, _ := l.Allow(ctx, "a"); r.Allowed {
		t.Fatal("a second request should be limited")
	}
	if r, _ := l.Allow(ctx, "b"); !r.Allowed {
		t.Fatal("b must not be affected by a")
	}
}

func TestNewRedisValidatesPolicy(t *testing.T) {
	if _, err := NewRedis(redis.NewClient(&redis.Options{}), "x", Policy{}); err == nil {
		t.Fatal("expected error for zero policy")
	}
}

func TestLeakyBucketConcurrentAtomicity(t *testing.T) {
	const capacity, callers = 10, 100
	l, _ := newTestLimiter(t, Policy{Capacity: capacity, LeakPerSec: 1})

	var allowed atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if r, err := l.Allow(context.Background(), "shared"); err == nil && r.Allowed {
				allowed.Add(1)
			}
		}()
	}
	wg.Wait()
	if got := allowed.Load(); got != capacity {
		t.Fatalf("allowed %d, want exactly %d", got, capacity)
	}
}

func TestLeakyBucketRemainingAndRetryAfter(t *testing.T) {
	l, _ := newTestLimiter(t, Policy{Capacity: 4, LeakPerSec: 2})
	r, _ := l.Allow(context.Background(), "k")
	if r.Limit != 4 || r.Remaining != 3 {
		t.Fatalf("limit/remaining = %d/%d", r.Limit, r.Remaining)
	}
	for i := 0; i < 3; i++ {
		l.Allow(context.Background(), "k")
	}
	r, _ = l.Allow(context.Background(), "k")
	if r.Allowed || r.RetryAfter != 500*time.Millisecond {
		t.Fatalf("allowed=%v retry=%v", r.Allowed, r.RetryAfter)
	}
}

func TestLeakyBucket_TestcontainersRedis(t *testing.T) {
	client := testdb.RedisClient(t)
	l, err := NewRedis(client, "rl:tc", Policy{Capacity: 3, LeakPerSec: 1})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		res, err := l.Allow(ctx, "tc-client")
		if err != nil || !res.Allowed {
			t.Fatalf("request %d: allowed=%v err=%v", i, res.Allowed, err)
		}
	}
	res, err := l.Allow(ctx, "tc-client")
	if err != nil {
		t.Fatal(err)
	}
	if res.Allowed {
		t.Fatal("4th request should be rate limited on real Redis container")
	}
}
