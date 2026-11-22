package secrets

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	secretsv1 "github.com/skxm03/kr0n-backend/control-plane/gen/secrets/v1"
	"github.com/skxm03/kr0n-backend/control-plane/internal/database"
	"github.com/skxm03/kr0n-backend/control-plane/internal/secrets/config"
	"github.com/skxm03/kr0n-backend/control-plane/internal/secrets/crypto"
	"github.com/skxm03/kr0n-backend/control-plane/internal/secrets/handlers"
	"github.com/skxm03/kr0n-backend/control-plane/internal/secrets/repository"
	"github.com/skxm03/kr0n-backend/control-plane/internal/secrets/service"
	pkgAudit "github.com/skxm03/kr0n-backend/control-plane/pkg/audit"
)

// App encapsulates the dedicated Secrets & Vault gRPC microservice dependencies and lifecycle.
type App struct {
	cfg          *config.Config
	dbPool       *pgxpool.Pool
	auditEmitter pkgAudit.Emitter
	grpcServer   *grpc.Server
}

// NewApp wires the PostgreSQL pool, Master KEK KeyManager, RabbitMQ audit emitter, SecretsService, and gRPC server.
func NewApp(ctx context.Context, cfg *config.Config) (*App, error) {
	dbPool, err := database.NewPostgresPool(ctx, cfg.DatabaseURL)
	if err != nil {
		return nil, err
	}

	var auditEmitter pkgAudit.Emitter
	if strings.TrimSpace(cfg.AuditRabbitMQURL) != "" {
		emitter, err := pkgAudit.NewRabbitMQEmitter(pkgAudit.EmitterConfig{
			AMQPURL:      cfg.AuditRabbitMQURL,
			ServiceName:  "secrets",
			ExchangeName: cfg.AuditExchangeName,
		})
		if err != nil {
			dbPool.Close()
			return nil, fmt.Errorf("connect secrets audit rabbitmq emitter: %w", err)
		}
		auditEmitter = emitter
	}

	cleanup := func() {
		if auditEmitter != nil {
			_ = auditEmitter.Close()
		}
		dbPool.Close()
	}

	keyManager, err := crypto.NewKeyManagerFromPath(cfg.MasterKEKPath, cfg.MasterKEKVersion)
	if err != nil {
		cleanup()
		return nil, fmt.Errorf("load secrets master KEK (run 'make gen-kek' for local dev): %w", err)
	}

	secretsRepo := repository.NewPostgresSecretsRepository(dbPool)
	authorizer := service.NewLocalDBAuthorizer(dbPool)
	projectVerifier := service.NewLocalDBProjectVerifier(dbPool)
	secretsSvc := service.NewSecretsService(
		secretsRepo,
		keyManager,
		service.WithAuthorizer(authorizer),
		service.WithProjectVerifier(projectVerifier),
	)
	grpcHandler := handlers.NewServer(secretsSvc, handlers.WithAuditEmitter(auditEmitter))

	isDev := cfg.Env == "dev" || cfg.Env == "development"
	var serverOpts []grpc.ServerOption
	if cfg.TLSCertFile != "" && cfg.TLSKeyFile != "" {
		cert, err := tls.LoadX509KeyPair(cfg.TLSCertFile, cfg.TLSKeyFile)
		if err != nil {
			cleanup()
			return nil, fmt.Errorf("load secrets server cert/key: %w", err)
		}
		tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		}
		if caFile := cfg.EffectiveClientCAFile(); caFile != "" {
			caPEM, err := os.ReadFile(caFile)
			if err != nil {
				cleanup()
				return nil, fmt.Errorf("read client ca file: %w", err)
			}
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(caPEM) {
				cleanup()
				return nil, errors.New("failed to parse client ca cert: file contains no valid certificates")
			}
			tlsConfig.ClientCAs = pool
			tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
		}
		serverOpts = append(serverOpts, grpc.Creds(credentials.NewTLS(tlsConfig)))
	} else if !isDev {
		cleanup()
		return nil, errors.New("plaintext gRPC is only allowed when KR0N_ENV=dev")
	}

	grpcServer := grpc.NewServer(serverOpts...)
	secretsv1.RegisterSecretsServiceServer(grpcServer, grpcHandler)
	secretsv1.RegisterSecretsInternalServiceServer(grpcServer, grpcHandler)

	return &App{
		cfg:          cfg,
		dbPool:       dbPool,
		auditEmitter: auditEmitter,
		grpcServer:   grpcServer,
	}, nil
}

// Run starts the Secrets gRPC server and blocks until ctx is canceled.
func (a *App) Run(ctx context.Context) error {
	defer a.dbPool.Close()
	if a.auditEmitter != nil {
		defer a.auditEmitter.Close()
	}

	lis, err := net.Listen("tcp", a.cfg.GRPCAddr)
	if err != nil {
		return err
	}
	defer lis.Close()

	errChan := make(chan error, 1)
	go func() {
		log.Printf("secrets gRPC service listening on %s", a.cfg.GRPCAddr)
		if err := a.grpcServer.Serve(lis); err != nil && !errors.Is(err, grpc.ErrServerStopped) {
			errChan <- err
		}
		close(errChan)
	}()

	select {
	case <-ctx.Done():
		log.Println("shutting down secrets gRPC service gracefully...")
		stopped := make(chan struct{})
		go func() {
			a.grpcServer.GracefulStop()
			close(stopped)
		}()
		select {
		case <-stopped:
			log.Println("secrets gRPC service stopped successfully")
		case <-time.After(10 * time.Second):
			log.Println("secrets gRPC graceful shutdown timed out, forcing stop")
			a.grpcServer.Stop()
		}
		return nil
	case err := <-errChan:
		return err
	}
}
