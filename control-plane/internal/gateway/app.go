package gateway

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/redis/go-redis/v9"
	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"

	authv1 "github.com/skxm03/kr0n-backend/control-plane/gen/auth/v1"
	"github.com/skxm03/kr0n-backend/control-plane/internal/auth/jwtkeys"
	"github.com/skxm03/kr0n-backend/control-plane/internal/email"
	"github.com/skxm03/kr0n-backend/control-plane/internal/gateway/config"
	dynamicconfig "github.com/skxm03/kr0n-backend/control-plane/internal/gateway/dynamic/config"
	dynamicregistry "github.com/skxm03/kr0n-backend/control-plane/internal/gateway/dynamic/registry"
	dynamicrouter "github.com/skxm03/kr0n-backend/control-plane/internal/gateway/dynamic/router"
	dynamicwatcher "github.com/skxm03/kr0n-backend/control-plane/internal/gateway/dynamic/watcher"
	"github.com/skxm03/kr0n-backend/control-plane/internal/gateway/middleware"
	"github.com/skxm03/kr0n-backend/control-plane/internal/gateway/middleware/builtins"
	"github.com/skxm03/kr0n-backend/control-plane/internal/gateway/ratelimit"
)

// App encapsulates the API Gateway HTTP server and its backing connections.
type App struct {
	authConn   *grpc.ClientConn
	rdb        *redis.Client
	rmqSender  *email.RabbitMQSender
	server     *http.Server
	dynManager *dynamicrouter.Manager
	dynWatcher *dynamicwatcher.Watcher
}

// NewApp wires the Auth gRPC client, JWKS verifier, Redis rate limiters, and HTTP router.
func NewApp(cfg *config.Config) (*App, error) {
	isDev := cfg.Env == "dev" || cfg.Env == "development"

	authConn, err := DialUpstream(cfg.AuthGRPCAddr, DialUpstreamTLSConfig{
		Enabled:    cfg.AuthGRPCTLSEnabled,
		CertFile:   cfg.AuthGRPCTLSCertFile,
		KeyFile:    cfg.AuthGRPCTLSKeyFile,
		CAFile:     cfg.AuthGRPCTLSCAFile,
		ServerName: cfg.AuthGRPCServerName,
	}, cfg.AuthServiceToken, isDev)
	if err != nil {
		return nil, fmt.Errorf("dial auth gRPC service %q: %w", cfg.AuthGRPCAddr, err)
	}

	var pubKeys map[string]ed25519.PublicKey
	if cfg.JWTPublicKeys != "" {
		pubKeys, err = jwtkeys.ParsePublicKeys(cfg.JWTPublicKeys)
		if err != nil {
			_ = authConn.Close()
			return nil, fmt.Errorf("invalid JWT_PUBLIC_KEYS: %w", err)
		}
	} else if isDev {
		pubKeys = map[string]ed25519.PublicKey{
			cfg.JWTKeyID: jwtkeys.DevPrivateKey().Public().(ed25519.PublicKey),
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

	rdb := redis.NewClient(&redis.Options{Addr: cfg.RedisAddr})
	generalLimiter, err := ratelimit.NewRedis(rdb, "rl:general", ratelimit.Policy{
		Capacity:   cfg.GeneralRateCapacity,
		LeakPerSec: cfg.GeneralRatePerSec,
	})
	if err != nil {
		_ = rdb.Close()
		_ = authConn.Close()
		return nil, err
	}
	authLimiter, err := ratelimit.NewRedis(rdb, "rl:auth", ratelimit.Policy{
		Capacity:   cfg.AuthRateCapacity,
		LeakPerSec: cfg.AuthRatePerSec,
	})
	if err != nil {
		_ = rdb.Close()
		_ = authConn.Close()
		return nil, err
	}

	var rmqSender *email.RabbitMQSender
	if cfg.RabbitMQURL != "" {
		rmqSender, err = email.NewRabbitMQSender(cfg.RabbitMQURL, cfg.EmailQueueName)
		if err != nil {
			_ = rdb.Close()
			_ = authConn.Close()
			return nil, fmt.Errorf("connect rabbitmq email sender: %w", err)
		}
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	var primaryHandler http.Handler = NewServerHandler(NewHandler(authClient), Options{
		Env:            cfg.Env,
		Log:            logger,
		Verifier:       verifier,
		GeneralLimiter: generalLimiter,
		AuthLimiter:    authLimiter,
		TrustedProxies: trustedProxies,
		Ready: func(context.Context) error {
			if authConn.GetState() == connectivity.Shutdown || authConn.GetState() == connectivity.TransientFailure {
				return errors.New("auth service unreachable")
			}
			return nil
		},
	})

	var dynManager *dynamicrouter.Manager
	var dynWatcher *dynamicwatcher.Watcher

	// Check if dynamic YAML configuration is available
	if cfg.GatewayConfigPath != "" {
		if _, err := os.Stat(cfg.GatewayConfigPath); err == nil {
			dynCfg, err := dynamicconfig.LoadConfigFile(cfg.GatewayConfigPath)
			if err != nil {
				_ = rdb.Close()
				_ = authConn.Close()
				return nil, fmt.Errorf("load dynamic gateway config from %q: %w", cfg.GatewayConfigPath, err)
			}

			apiTokenVerifier := NewGRPCAPITokenVerifier(authClient)
			mwReg := middleware.NewRegistry()
			_ = builtins.RegisterDefaults(mwReg, builtins.SharedDeps{
				Logger:           logger,
				Verifier:         verifier,
				APITokenVerifier: apiTokenVerifier,
				Limiter:          generalLimiter,
				TrustedProxies:   trustedProxies,
				MaxBodyBytes:     1 << 20,
			})
			mwReg.Freeze()

			dynManager = dynamicrouter.NewManager(dynamicrouter.ManagerOptions{
				Registry:           dynamicregistry.DefaultRegistry(),
				MiddlewareRegistry: mwReg,
				Dialer: func(svc dynamicconfig.ServiceConfig) (*grpc.ClientConn, error) {
					return DialUpstream(svc.Address, DialUpstreamTLSConfig{
						Enabled:    svc.TLS.Enabled,
						CertFile:   svc.TLS.CertFile,
						KeyFile:    svc.TLS.KeyFile,
						CAFile:     svc.TLS.CAFile,
						ServerName: svc.TLS.ServerName,
					}, svc.ServiceToken, isDev)
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
				_ = rdb.Close()
				_ = authConn.Close()
				return nil, fmt.Errorf("initialize dynamic gateway router: %w", err)
			}

			dynWatcher, err = dynamicwatcher.NewWatcher(cfg.GatewayConfigPath, 100*time.Millisecond, func(ctx context.Context, path string) error {
				newCfg, err := dynamicconfig.LoadConfigFile(path)
				if err != nil {
					return err
				}
				return dynManager.Reload(ctx, newCfg)
			}, logger)
			if err != nil {
				_ = rdb.Close()
				_ = authConn.Close()
				return nil, fmt.Errorf("initialize dynamic config watcher: %w", err)
			}

			primaryHandler = dynManager
			logger.Info("dynamic YAML gateway routing initialized", "config_path", cfg.GatewayConfigPath)
		}
	}

	server := &http.Server{
		Addr:              cfg.GatewayHTTPAddr,
		Handler:           primaryHandler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	return &App{
		authConn:   authConn,
		rdb:        rdb,
		rmqSender:  rmqSender,
		server:     server,
		dynManager: dynManager,
		dynWatcher: dynWatcher,
	}, nil
}

// Run starts the HTTP server and blocks until ctx is canceled or the server fails.
func (a *App) Run(ctx context.Context) error {
	defer a.authConn.Close()
	defer a.rdb.Close()
	if a.rmqSender != nil {
		defer a.rmqSender.Close()
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
