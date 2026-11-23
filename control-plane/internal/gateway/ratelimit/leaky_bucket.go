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

// Redis is a Limiter that stores bucket state in Redis using an atomic Lua script.
type Redis struct {
	client *redis.Client
	policy Policy
	prefix string
	script *redis.Script
}

const leakyBucketLua = `
local key = KEYS[1]
local capacity = tonumber(ARGV[1])
local leakPerSec = tonumber(ARGV[2])
local ttlMs = tonumber(ARGV[3])
local nowMs = tonumber(ARGV[4])

-- Use Redis TIME if available and valid
local timeRes = redis.pcall('TIME')
if type(timeRes) == 'table' and #timeRes >= 2 then
    local s = tonumber(timeRes[1])
    local us = tonumber(timeRes[2])
    if s and us then
        nowMs = s * 1000 + math.floor(us / 1000)
    end
end

local state = redis.call('HMGET', key, 'level', 'ts')
local level = 0
local ts = nowMs

if state[1] and state[1] ~= false then
    level = tonumber(state[1]) or 0
end
if state[2] and state[2] ~= false then
    ts = tonumber(state[2]) or nowMs
end

local elapsedSec = (nowMs - ts) / 1000.0
if elapsedSec > 0 then
    level = math.max(0, level - (elapsedSec * leakPerSec))
end

local allowed = 0
local retryMs = 0
if level + 1 <= capacity then
    level = level + 1
    allowed = 1
else
    retryMs = math.ceil(((level + 1 - capacity) / leakPerSec) * 1000)
end

redis.call('HSET', key, 'level', tostring(level), 'ts', tostring(nowMs))
redis.call('PEXPIRE', key, ttlMs)

local remaining = math.max(0, math.floor(capacity - level))
return { allowed, remaining, retryMs }
`

// NewRedis returns a Redis-backed leaky-bucket limiter. prefix namespaces keys (e.g. "rl:auth").
func NewRedis(client *redis.Client, prefix string, p Policy) (*Redis, error) {
	if client == nil {
		return nil, errors.New("ratelimit: nil redis client")
	}
	if p.Capacity < 1 || p.LeakPerSec <= 0 {
		return nil, fmt.Errorf("ratelimit: invalid policy %+v", p)
	}
	return &Redis{
		client: client,
		policy: p,
		prefix: prefix,
		script: redis.NewScript(leakyBucketLua),
	}, nil
}

// Allow implements Limiter atomically in a single Redis round-trip via Lua script execution.
func (r *Redis) Allow(ctx context.Context, key string) (Result, error) {
	fullKey := r.prefix + ":" + key
	capacity := float64(r.policy.Capacity)
	ttl := time.Duration(math.Ceil((capacity/r.policy.LeakPerSec)*1000)+1000) * time.Millisecond
	ttlMs := ttl.Milliseconds()
	nowMs := time.Now().UnixMilli()

	res, err := r.script.Run(ctx, r.client, []string{fullKey},
		r.policy.Capacity,
		r.policy.LeakPerSec,
		ttlMs,
		nowMs,
	).Result()
	if err != nil {
		return Result{}, fmt.Errorf("ratelimit: %w", err)
	}

	vals, ok := res.([]any)
	if !ok || len(vals) < 3 {
		return Result{}, fmt.Errorf("ratelimit: unexpected script response: %v", res)
	}

	allowedInt, _ := toInt64(vals[0])
	remainingInt, _ := toInt64(vals[1])
	retryMsInt, _ := toInt64(vals[2])

	return Result{
		Allowed:    allowedInt == 1,
		Limit:      r.policy.Capacity,
		Remaining:  int(remainingInt),
		RetryAfter: time.Duration(retryMsInt) * time.Millisecond,
	}, nil
}

func toInt64(v any) (int64, bool) {
	switch n := v.(type) {
	case int64:
		return n, true
	case int:
		return int64(n), true
	case float64:
		return int64(n), true
	case string:
		i, err := strconv.ParseInt(n, 10, 64)
		return i, err == nil
	default:
		return 0, false
	}
}
