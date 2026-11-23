package gateway

import (
	"cmp"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/redis/go-redis/v9"
	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"

	authv1 "github.com/skxm03/kr0n-backend/control-plane/gen/auth/v1"
	"github.com/skxm03/kr0n-backend/control-plane/internal/auth/jwtkeys"
	"github.com/skxm03/kr0n-backend/control-plane/internal/gateway/config"
	dynamicconfig "github.com/skxm03/kr0n-backend/control-plane/internal/gateway/dynamic/config"
	dynamicregistry "github.com/skxm03/kr0n-backend/control-plane/internal/gateway/dynamic/registry"
	dynamicrouter "github.com/skxm03/kr0n-backend/control-plane/internal/gateway/dynamic/router"
	dynamicwatcher "github.com/skxm03/kr0n-backend/control-plane/internal/gateway/dynamic/watcher"
	"github.com/skxm03/kr0n-backend/control-plane/internal/gateway/middleware"
	"github.com/skxm03/kr0n-backend/control-plane/internal/gateway/middleware/builtins"
	"github.com/skxm03/kr0n-backend/control-plane/internal/gateway/ratelimit"
	pkgAudit "github.com/skxm03/kr0n-backend/control-plane/pkg/audit"
)

// App encapsulates the API Gateway HTTP server and its backing connections.
type App struct {
	authConn     *grpc.ClientConn
	rdb          *redis.Client
	auditEmitter pkgAudit.Emitter
	server       *http.Server
	dynManager   *dynamicrouter.Manager
	dynWatcher   *dynamicwatcher.Watcher
}

// NewApp wires the Auth gRPC client, JWKS verifier, Redis rate limiters, and dynamic HTTP router.
func NewApp(cfg *config.Config) (*App, error) {
	isDev := cfg.Env == "dev" || cfg.Env == "development"

	// 1. Load dynamic YAML configuration as single authoritative topology source
	if cfg == nil || strings.TrimSpace(cfg.GatewayConfigPath) == "" {
		return nil, errors.New("gateway config is nil or GATEWAY_CONFIG_PATH is not set")
	}
	configPath := strings.TrimSpace(cfg.GatewayConfigPath)
	dynCfg, err := dynamicconfig.LoadConfigFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("load dynamic gateway config from %q: %w", configPath, err)
	}

	// 2. Resolve auth address (env override or dynamic config fallback)
	authAddr := cmp.Or(strings.TrimSpace(cfg.AuthGRPCAddr), dynCfg.Services["auth"].Address)
	if authAddr == "" {
		return nil, errors.New(`service "auth" has no address configured in YAML or .env (AUTH_GRPC_ADDR)`)
	}
	if authSvc, ok := dynCfg.Services["auth"]; ok {
		authSvc.Address = authAddr
		dynCfg.Services["auth"] = authSvc
	}

	// 3. Dial upstream for auth client (used by JWKS key set provider & API token verifier)
	insecureAuth := isDev && cfg.AuthGRPCTLSCertFile == "" && cfg.AuthGRPCTLSCAFile == ""
	authConn, err := DialUpstream(authAddr, DialUpstreamTLSConfig{
		Insecure:   insecureAuth,
		CertFile:   cfg.AuthGRPCTLSCertFile,
		KeyFile:    cfg.AuthGRPCTLSKeyFile,
		CAFile:     cfg.AuthGRPCTLSCAFile,
		ServerName: cfg.AuthGRPCServerName,
	})
	if err != nil {
		return nil, fmt.Errorf("dial auth gRPC service %q: %w", authAddr, err)
	}

	// 4. Set up JWT Verifier (optional static keys, or dynamically resolved via JWKS over gRPC)
	var pubKeys map[string]ed25519.PublicKey
	if cfg.JWTPublicKeys != "" {
		pubKeys, err = jwtkeys.ParsePublicKeys(cfg.JWTPublicKeys)
		if err != nil {
			_ = authConn.Close()
			return nil, fmt.Errorf("invalid JWT_PUBLIC_KEYS: %w", err)
		}
	}

	var trustedProxies []*net.IPNet
	for _, cidr := range cfg.TrustedProxyCIDRs {
		if cidr == "" {
			continue
		}
		_, n, err := net.ParseCIDR(cidr)
		if err != nil {
			_ = authConn.Close()
			return nil, fmt.Errorf("invalid TRUSTED_PROXY_CIDRS entry %q: %w", cidr, err)
		}
		trustedProxies = append(trustedProxies, n)
	}

	authClient := authv1.NewAuthServiceClient(authConn)
	verifier, err := jwtkeys.NewVerifier(
		pubKeys,
		cfg.JWTIssuer,
		cfg.JWTAudience,
		jwtkeys.WithKeySetProvider(NewGRPCJWKSProvider(authClient), 5*time.Second),
	)
	if err != nil {
		_ = authConn.Close()
		return nil, err
	}

	// 5. Connect Redis client & default rate limiter
	rdb := redis.NewClient(&redis.Options{Addr: cfg.RedisAddr})
	generalLimiter, err := ratelimit.NewRedis(rdb, "rl:general", ratelimit.Policy{
		Capacity:   120,
		LeakPerSec: 20,
	})
	if err != nil {
		_ = rdb.Close()
		_ = authConn.Close()
		return nil, err
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	apiTokenVerifier := NewGRPCAPITokenVerifier(authClient)

	var auditEmitter pkgAudit.Emitter
	if strings.TrimSpace(cfg.AuditRabbitMQURL) != "" {
		emitter, err := pkgAudit.NewRabbitMQEmitter(pkgAudit.EmitterConfig{
			AMQPURL:      cfg.AuditRabbitMQURL,
			ServiceName:  "gateway",
			ExchangeName: cfg.AuditExchangeName,
		})
		if err != nil {
			_ = rdb.Close()
			_ = authConn.Close()
			return nil, fmt.Errorf("connect gateway audit rabbitmq emitter: %w", err)
		}
		auditEmitter = emitter
	}

	// 6. Build Middleware Registry
	mwReg := middleware.NewRegistry()
	_ = builtins.RegisterDefaults(mwReg, builtins.SharedDeps{
		Logger:           logger,
		AuditEmitter:     auditEmitter,
		Verifier:         verifier,
		APITokenVerifier: apiTokenVerifier,
		Limiter:          generalLimiter,
		RedisClient:      rdb,
		TrustedProxies:   trustedProxies,
		MaxBodyBytes:     dynCfg.Gateway.MaxBodyBytes,
	})
	mwReg.Freeze()

	// 7. Dynamic Router Manager (Unified Single HTTP Engine)
	dynManager := dynamicrouter.NewManager(dynamicrouter.ManagerOptions{
		Registry:           dynamicregistry.DefaultRegistry(),
		MiddlewareRegistry: mwReg,
		Dialer: func(svc dynamicconfig.ServiceConfig) (*grpc.ClientConn, error) {
			insecure := isDev && svc.TLS.CAFile == ""
			return DialUpstream(svc.Address, DialUpstreamTLSConfig{
				Insecure:   insecure,
				CertFile:   svc.TLS.CertFile,
				KeyFile:    svc.TLS.KeyFile,
				CAFile:     svc.TLS.CAFile,
				ServerName: svc.TLS.ServerName,
			})
		},
		MuxFactory: func() *runtime.ServeMux {
			return NewGatewayServeMux(trustedProxies)
		},
		ReadyCheck: func(ctx context.Context) error {
			if authConn.GetState() == connectivity.Shutdown || authConn.GetState() == connectivity.TransientFailure {
				return errors.New("auth service unreachable")
			}
			return nil
		},
		SafetyTimeout: 30 * time.Second,
	})

	if err := dynManager.Initialize(context.Background(), dynCfg); err != nil {
		if auditEmitter != nil {
			_ = auditEmitter.Close()
		}
		_ = rdb.Close()
		_ = authConn.Close()
		return nil, fmt.Errorf("initialize dynamic gateway router: %w", err)
	}

	// 8. Dynamic File Watcher
	dynWatcher, err := dynamicwatcher.NewWatcher(configPath, 100*time.Millisecond, func(ctx context.Context, path string) error {
		newCfg, err := dynamicconfig.LoadConfigFile(path)
		if err != nil {
			return err
		}
		return dynManager.Reload(ctx, newCfg)
	}, logger)
	if err != nil {
		if auditEmitter != nil {
			_ = auditEmitter.Close()
		}
		_ = rdb.Close()
		_ = authConn.Close()
		return nil, fmt.Errorf("initialize dynamic config watcher: %w", err)
	}

	// 9. HTTP Server with YAML topology
	server := &http.Server{
		Addr:              cmp.Or(cfg.GatewayHTTPAddr, dynCfg.Gateway.HTTPAddr, ":8080"),
		Handler:           dynManager,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       dynCfg.Gateway.ReadTimeout,
		WriteTimeout:      dynCfg.Gateway.WriteTimeout,
		IdleTimeout:       dynCfg.Gateway.IdleTimeout,
	}

	return &App{
		authConn:     authConn,
		rdb:          rdb,
		auditEmitter: auditEmitter,
		server:       server,
		dynManager:   dynManager,
		dynWatcher:   dynWatcher,
	}, nil
}

// Run starts the HTTP server and blocks until ctx is canceled or the server fails.
func (a *App) Run(ctx context.Context) error {
	defer a.authConn.Close()
	defer a.rdb.Close()
	if a.auditEmitter != nil {
		defer a.auditEmitter.Close()
	}
	if a.dynManager != nil {
		defer a.dynManager.Close()
	}
	if a.dynWatcher != nil {
		if err := a.dynWatcher.Start(ctx); err != nil {
			return fmt.Errorf("start dynamic config watcher: %w", err)
		}
		defer a.dynWatcher.Stop()
	}

	errChan := make(chan error, 1)
	go func() {
		log.Printf("API gateway HTTP service listening on %s", a.server.Addr)
		if err := a.server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errChan <- err
		}
		close(errChan)
	}()

	select {
	case <-ctx.Done():
		log.Println("shutting down API gateway HTTP service gracefully...")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := a.server.Shutdown(shutdownCtx); err != nil {
			log.Printf("HTTP shutdown error: %v", err)
			_ = a.server.Close()
		}
		return nil
	case err := <-errChan:
		return err
	}
}
