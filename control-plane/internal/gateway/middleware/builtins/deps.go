package builtins

import (
	"log/slog"
	"net"

	"github.com/redis/go-redis/v9"

	"github.com/skxm03/kr0n-backend/control-plane/internal/gateway/middleware"
	"github.com/skxm03/kr0n-backend/control-plane/internal/gateway/ratelimit"
	pkgAudit "github.com/skxm03/kr0n-backend/control-plane/pkg/audit"
)

// SharedDeps contains long-lived, application-level dependencies that persist across
// router snapshot reloads (such as token verifiers, Redis clients, and loggers).
type SharedDeps struct {
	Logger           *slog.Logger
	AuditEmitter     pkgAudit.Emitter
	Verifier         middleware.TokenVerifier
	APITokenVerifier middleware.APITokenVerifier
	Limiter          ratelimit.Limiter
	LimiterFactory   func(prefix string, policy ratelimit.Policy) (ratelimit.Limiter, error)
	RedisClient      *redis.Client
	TrustedProxies   []*net.IPNet
	MaxBodyBytes     int64
}
