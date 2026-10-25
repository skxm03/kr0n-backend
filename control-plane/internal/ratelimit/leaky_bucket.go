// Package ratelimit implements a distributed leaky-bucket (meter) rate limiter backed by Redis.
package ratelimit

import (
	"context"
	"errors"
	"fmt"
	"math"
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

// The script uses Redis TIME so every gateway replica shares one clock.
// level drains continuously; a request is admitted only if it fits in the remaining capacity.
var leakyScript = redis.NewScript(`
local t = redis.call('TIME')
local now = tonumber(t[1]) * 1000 + math.floor(tonumber(t[2]) / 1000)
local capacity = tonumber(ARGV[1])
local leak = tonumber(ARGV[2])

local state = redis.call('HMGET', KEYS[1], 'level', 'ts')
local level = tonumber(state[1]) or 0
local ts = tonumber(state[2]) or now

level = math.max(0, level - ((now - ts) / 1000) * leak)

local allowed = 0
local retry = 0
if level + 1 <= capacity then
  level = level + 1
  allowed = 1
else
  retry = math.ceil(((level + 1 - capacity) / leak) * 1000)
end

redis.call('HSET', KEYS[1], 'level', tostring(level), 'ts', tostring(now))
redis.call('PEXPIRE', KEYS[1], math.ceil((capacity / leak) * 1000) + 1000)
return {allowed, math.floor(capacity - level), retry}
`)

// Redis is a Limiter that stores bucket state in Redis.
type Redis struct {
	client redis.Scripter
	policy Policy
	prefix string
}

// NewRedis returns a Redis-backed leaky-bucket limiter. prefix namespaces keys (e.g. "rl:auth").
func NewRedis(client redis.Scripter, prefix string, p Policy) (*Redis, error) {
	if client == nil {
		return nil, errors.New("ratelimit: nil redis client")
	}
	if p.Capacity < 1 || p.LeakPerSec <= 0 {
		return nil, fmt.Errorf("ratelimit: invalid policy %+v", p)
	}
	return &Redis{client: client, policy: p, prefix: prefix}, nil
}

// Allow implements Limiter.
func (r *Redis) Allow(ctx context.Context, key string) (Result, error) {
	res, err := leakyScript.Run(ctx, r.client, []string{r.prefix + ":" + key}, r.policy.Capacity, r.policy.LeakPerSec).Int64Slice()
	if err != nil {
		return Result{}, fmt.Errorf("ratelimit: %w", err)
	}
	if len(res) != 3 {
		return Result{}, errors.New("ratelimit: unexpected script reply")
	}
	return Result{
		Allowed:    res[0] == 1,
		Limit:      r.policy.Capacity,
		Remaining:  int(math.Max(0, float64(res[1]))),
		RetryAfter: time.Duration(res[2]) * time.Millisecond,
	}, nil
}
