package gateway

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/redis/go-redis/v9"
	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	authv1 "github.com/skxm03/kr0n-backend/control-plane/gen/auth/v1"
	"github.com/skxm03/kr0n-backend/control-plane/internal/auth/jwtkeys"
	"github.com/skxm03/kr0n-backend/control-plane/internal/gateway/config"
	"github.com/skxm03/kr0n-backend/control-plane/internal/gateway/ratelimit"
)

// App encapsulates the API Gateway HTTP server and its backing connections.
type App struct {
	authConn *grpc.ClientConn
	rdb      *redis.Client
	server   *http.Server
}

// NewApp wires the Auth gRPC client, JWKS verifier, Redis rate limiters, and HTTP router.
func NewApp(cfg *config.Config) (*App, error) {
	isDev := cfg.Env == "dev" || cfg.Env == "development"
	tlsPlain := isDev && cfg.AuthGRPCTLSCAFile == "" && !cfg.AuthGRPCTLSEnabled

	var dialOpts []grpc.DialOption
	var dialCreds credentials.TransportCredentials
	if cfg.AuthGRPCTLSCertFile != "" && cfg.AuthGRPCTLSKeyFile != "" {
		cert, err := tls.LoadX509KeyPair(cfg.AuthGRPCTLSCertFile, cfg.AuthGRPCTLSKeyFile)
		if err != nil {
			return nil, fmt.Errorf("load gateway client cert/key: %w", err)
		}
		tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{cert},
			ServerName:   cfg.AuthGRPCServerName,
			MinVersion:   tls.VersionTLS12,
		}
		if cfg.AuthGRPCTLSCAFile != "" {
			caPEM, err := os.ReadFile(cfg.AuthGRPCTLSCAFile)
			if err != nil {
				return nil, fmt.Errorf("read auth ca file: %w", err)
			}
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(caPEM) {
				return nil, errors.New("failed to parse auth ca cert: file contains no valid certificates")
			}
			tlsConfig.RootCAs = pool
		}
		dialCreds = credentials.NewTLS(tlsConfig)
	} else if cfg.AuthGRPCTLSCAFile != "" {
		caPEM, err := os.ReadFile(cfg.AuthGRPCTLSCAFile)
		if err != nil {
			return nil, fmt.Errorf("read auth ca file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, errors.New("failed to parse auth ca cert: file contains no valid certificates")
		}
		tlsConfig := &tls.Config{
			RootCAs:    pool,
			ServerName: cfg.AuthGRPCServerName,
			MinVersion: tls.VersionTLS12,
		}
		dialCreds = credentials.NewTLS(tlsConfig)
	} else if !tlsPlain {
		dialCreds = credentials.NewTLS(&tls.Config{
			ServerName: cfg.AuthGRPCServerName,
			MinVersion: tls.VersionTLS12,
		})
	} else if isDev {
		dialCreds = insecure.NewCredentials()
	} else {
		return nil, errors.New("plaintext Auth gRPC is only allowed when KR0N_ENV=dev")
	}

	dialOpts = append(dialOpts, grpc.WithTransportCredentials(dialCreds))
	if cfg.AuthServiceToken != "" {
		dialOpts = append(dialOpts, grpc.WithUnaryInterceptor(ServiceTokenClientInterceptor(cfg.AuthServiceToken)))
	}

	authConn, err := grpc.NewClient(cfg.AuthGRPCAddr, dialOpts...)
	if err != nil {
		return nil, err
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

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	router := NewServerHandler(NewHandler(authClient), Options{
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

	server := &http.Server{
		Addr:              cfg.GatewayHTTPAddr,
		Handler:           router,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	return &App{
		authConn: authConn,
		rdb:      rdb,
		server:   server,
	}, nil
}

// Run starts the HTTP server and blocks until ctx is canceled or the server fails.
func (a *App) Run(ctx context.Context) error {
	defer a.authConn.Close()
	defer a.rdb.Close()

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
