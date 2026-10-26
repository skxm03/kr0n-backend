package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/redis/go-redis/v9"
	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	authv1 "github.com/skxm03/kr0n-backend/control-plane/gen/auth/v1"
	"github.com/skxm03/kr0n-backend/control-plane/internal/auth/jwtkeys"
	"github.com/skxm03/kr0n-backend/control-plane/internal/config"
	"github.com/skxm03/kr0n-backend/control-plane/internal/gateway"
	"github.com/skxm03/kr0n-backend/control-plane/internal/ratelimit"
)

func main() {
	if err := run(); err != nil {
		log.Printf("gateway service error: %v", err)
		os.Exit(1)
	}
	log.Println("gateway service stopped cleanly")
}

func run() error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cfg, err := config.LoadGateway()
	if err != nil {
		return err
	}

	var dialOpts []grpc.DialOption
	var dialCreds credentials.TransportCredentials
	if cfg.AuthGRPCTLSCertFile != "" && cfg.AuthGRPCTLSKeyFile != "" {
		cert, err := tls.LoadX509KeyPair(cfg.AuthGRPCTLSCertFile, cfg.AuthGRPCTLSKeyFile)
		if err != nil {
			return fmt.Errorf("load gateway client cert/key: %w", err)
		}
		tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{cert},
			ServerName:   cfg.AuthGRPCServerName,
			MinVersion:   tls.VersionTLS12,
		}
		if cfg.AuthGRPCTLSCAFile != "" {
			caPEM, err := os.ReadFile(cfg.AuthGRPCTLSCAFile)
			if err != nil {
				return fmt.Errorf("read auth ca file: %w", err)
			}
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(caPEM) {
				return errors.New("failed to parse auth ca cert: file contains no valid certificates")
			}
			tlsConfig.RootCAs = pool
		}
		dialCreds = credentials.NewTLS(tlsConfig)
	} else if cfg.AuthGRPCTLSCAFile != "" {
		caPEM, err := os.ReadFile(cfg.AuthGRPCTLSCAFile)
		if err != nil {
			return fmt.Errorf("read auth ca file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return errors.New("failed to parse auth ca cert: file contains no valid certificates")
		}
		tlsConfig := &tls.Config{
			RootCAs:    pool,
			ServerName: cfg.AuthGRPCServerName,
			MinVersion: tls.VersionTLS12,
		}
		dialCreds = credentials.NewTLS(tlsConfig)
	} else if !cfg.AuthGRPCTLSPlain {
		dialCreds = credentials.NewTLS(&tls.Config{
			ServerName: cfg.AuthGRPCServerName,
			MinVersion: tls.VersionTLS12,
		})
	} else if cfg.Env == "dev" {
		dialCreds = insecure.NewCredentials()
	} else {
		return errors.New("plaintext Auth gRPC is only allowed when KR0N_ENV=dev")
	}

	dialOpts = append(dialOpts, grpc.WithTransportCredentials(dialCreds))
	if cfg.AuthServiceToken != "" {
		dialOpts = append(dialOpts, grpc.WithUnaryInterceptor(gateway.ServiceTokenClientInterceptor(cfg.AuthServiceToken)))
	}

	authConn, err := grpc.NewClient(cfg.AuthGRPCAddr, dialOpts...)
	if err != nil {
		return err
	}
	defer authConn.Close()

	authClient := authv1.NewAuthServiceClient(authConn)
	verifier, err := jwtkeys.NewVerifier(
		cfg.JWTPublicKeys,
		cfg.JWTIssuer,
		cfg.JWTAudience,
		jwtkeys.WithKeySetProvider(gateway.NewGRPCJWKSProvider(authClient), 5*time.Second),
	)
	if err != nil {
		return err
	}

	rdb := redis.NewClient(&redis.Options{Addr: cfg.RedisAddr})
	defer rdb.Close()
	generalLimiter, err := ratelimit.NewRedis(rdb, "rl:general", ratelimit.Policy{Capacity: cfg.GeneralRateCapacity, LeakPerSec: cfg.GeneralRatePerSec})
	if err != nil {
		return err
	}
	authLimiter, err := ratelimit.NewRedis(rdb, "rl:auth", ratelimit.Policy{Capacity: cfg.AuthRateCapacity, LeakPerSec: cfg.AuthRatePerSec})
	if err != nil {
		return err
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	router := gateway.NewServerHandler(gateway.NewHandler(authClient), gateway.Options{
		Env:            cfg.Env,
		Log:            logger,
		Verifier:       verifier,
		GeneralLimiter: generalLimiter,
		AuthLimiter:    authLimiter,
		TrustedProxies: cfg.TrustedProxies,
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

	errChan := make(chan error, 1)
	go func() {
		log.Printf("API gateway HTTP service listening on %s", cfg.GatewayHTTPAddr)
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errChan <- err
		}
		close(errChan)
	}()

	select {
	case <-ctx.Done():
		log.Println("shutting down API gateway HTTP service gracefully...")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			log.Printf("HTTP shutdown error: %v", err)
			_ = server.Close()
		}
		return nil
	case err := <-errChan:
		return err
	}
}
