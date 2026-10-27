// Package ratelimit implements a distributed leaky-bucket (meter) rate limiter backed by Redis.
package ratelimit

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
)

// Policy describes a bucket: it holds at most Capacity requests and drains at LeakPerSec.
// Sustained throughput is therefore capped at LeakPerSec; Capacity is the tolerated burst.
type Policy struct {
	Capacity   int
	LeakPerSec float64
}

// Result is the outcome of a single Allow call.
type Result struct {
	Allowed    bool
	Limit      int
	Remaining  int
	RetryAfter time.Duration // only meaningful when !Allowed
}

// Limiter decides whether a request identified by key may proceed.
type Limiter interface {
	Allow(ctx context.Context, key string) (Result, error)
}

// Redis is a Limiter that stores bucket state in Redis using pure Go and optimistic locking (WATCH).
type Redis struct {
	client *redis.Client
	policy Policy
	prefix string
}

// NewRedis returns a Redis-backed leaky-bucket limiter. prefix namespaces keys (e.g. "rl:auth").
func NewRedis(client *redis.Client, prefix string, p Policy) (*Redis, error) {
	if client == nil {
		return nil, errors.New("ratelimit: nil redis client")
	}
	if p.Capacity < 1 || p.LeakPerSec <= 0 {
		return nil, fmt.Errorf("ratelimit: invalid policy %+v", p)
	}
	return &Redis{client: client, policy: p, prefix: prefix}, nil
}

// Allow implements Limiter in pure Go using Redis WATCH + MULTI/EXEC transactions.
func (r *Redis) Allow(ctx context.Context, key string) (Result, error) {
	fullKey := r.prefix + ":" + key
	capacity := float64(r.policy.Capacity)
	ttl := time.Duration(math.Ceil((capacity/r.policy.LeakPerSec)*1000)+1000) * time.Millisecond

	var out Result
	const maxRetries = 128

	for attempt := 0; attempt < maxRetries; attempt++ {
		err := r.client.Watch(ctx, func(tx *redis.Tx) error {
			nowTime, err := tx.Time(ctx).Result()
			if err != nil {
				return err
			}
			nowMs := float64(nowTime.UnixMilli())

			state, err := tx.HMGet(ctx, fullKey, "level", "ts").Result()
			if err != nil {
				return err
			}

			var level float64
			if len(state) > 0 && state[0] != nil {
				if s, ok := state[0].(string); ok {
					level, _ = strconv.ParseFloat(s, 64)
				}
			}

			ts := nowMs
			if len(state) > 1 && state[1] != nil {
				if s, ok := state[1].(string); ok {
					if parsed, err := strconv.ParseFloat(s, 64); err == nil {
						ts = parsed
					}
				}
			}

			elapsedSec := (nowMs - ts) / 1000.0
			level = math.Max(0, level-elapsedSec*r.policy.LeakPerSec)

			var allowed bool
			var retryMs int64
			if level+1 <= capacity {
				level += 1
				allowed = true
			} else {
				retryMs = int64(math.Ceil(((level + 1 - capacity) / r.policy.LeakPerSec) * 1000))
			}

			_, err = tx.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
				pipe.HSet(ctx, fullKey,
					"level", strconv.FormatFloat(level, 'f', -1, 64),
					"ts", strconv.FormatFloat(nowMs, 'f', -1, 64),
				)
				pipe.PExpire(ctx, fullKey, ttl)
				return nil
			})
			if err != nil {
				return err
			}

			out = Result{
				Allowed:    allowed,
				Limit:      r.policy.Capacity,
				Remaining:  int(math.Max(0, math.Floor(capacity-level))),
				RetryAfter: time.Duration(retryMs) * time.Millisecond,
			}
			return nil
		}, fullKey)

		if err == nil {
			return out, nil
		}
		if errors.Is(err, redis.TxFailedErr) {
			continue
		}
		return Result{}, fmt.Errorf("ratelimit: %w", err)
	}

	return Result{}, errors.New("ratelimit: transaction contention limit exceeded")
}
