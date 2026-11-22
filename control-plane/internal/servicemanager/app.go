package servicemanager

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

	servicemanagerv1 "github.com/skxm03/kr0n-backend/control-plane/gen/servicemanager/v1"
	"github.com/skxm03/kr0n-backend/control-plane/internal/database"
	"github.com/skxm03/kr0n-backend/control-plane/internal/servicemanager/config"
	"github.com/skxm03/kr0n-backend/control-plane/internal/servicemanager/handlers"
	"github.com/skxm03/kr0n-backend/control-plane/internal/servicemanager/repository"
	"github.com/skxm03/kr0n-backend/control-plane/internal/servicemanager/service"
	pkgAudit "github.com/skxm03/kr0n-backend/control-plane/pkg/audit"
	"github.com/skxm03/kr0n-backend/control-plane/pkg/grpcauth"
)

// App encapsulates the Service Manager gRPC microservice dependencies and lifecycle.
type App struct {
	cfg          *config.Config
	dbPool       *pgxpool.Pool
	auditEmitter pkgAudit.Emitter
	grpcServer   *grpc.Server
}

// NewApp wires the PostgreSQL pool, RabbitMQ audit emitter, ProjectService, and gRPC server.
func NewApp(ctx context.Context, cfg *config.Config) (*App, error) {
	dbPool, err := database.NewPostgresPool(ctx, cfg.DatabaseURL)
	if err != nil {
		return nil, err
	}

	var auditEmitter pkgAudit.Emitter
	if strings.TrimSpace(cfg.AuditRabbitMQURL) != "" {
		emitter, err := pkgAudit.NewRabbitMQEmitter(pkgAudit.EmitterConfig{
			AMQPURL:      cfg.AuditRabbitMQURL,
			ServiceName:  "servicemanager",
			ExchangeName: cfg.AuditExchangeName,
		})
		if err != nil {
			dbPool.Close()
			return nil, fmt.Errorf("connect servicemanager audit rabbitmq emitter: %w", err)
		}
		auditEmitter = emitter
	}

	cleanup := func() {
		if auditEmitter != nil {
			_ = auditEmitter.Close()
		}
		dbPool.Close()
	}

	projectRepo := repository.NewPostgresProjectRepository(dbPool)
	authorizer := service.NewLocalDBAuthorizer(dbPool)
	instVerifier := service.NewLocalDBInstallationVerifier(dbPool)
	projectSvc := service.NewProjectService(
		projectRepo,
		service.WithAuthorizer(authorizer),
		service.WithInstallationVerifier(instVerifier),
	)
	isDev := cfg.Env == "dev" || cfg.Env == "development"
	serviceAuthConfig := grpcauth.ServiceAuthConfig{
		Enabled:            !isDev || cfg.EffectiveClientCAFile() != "",
		RequireClientCert:  !isDev || cfg.EffectiveClientCAFile() != "",
		AllowedClientNames: cfg.AllowedClients,
		AllowInsecureDev:   isDev && cfg.EffectiveClientCAFile() == "",
	}

	grpcHandler := handlers.NewServer(
		projectSvc,
		handlers.WithAuditEmitter(auditEmitter),
		handlers.WithServiceAuthConfig(serviceAuthConfig),
	)

	var serverOpts []grpc.ServerOption
	if cfg.TLSCertFile != "" && cfg.TLSKeyFile != "" {
		cert, err := tls.LoadX509KeyPair(cfg.TLSCertFile, cfg.TLSKeyFile)
		if err != nil {
			cleanup()
			return nil, fmt.Errorf("load servicemanager server cert/key: %w", err)
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

	serverOpts = append(serverOpts, grpc.UnaryInterceptor(grpcauth.NewServiceAuthInterceptor(serviceAuthConfig)))

	grpcServer := grpc.NewServer(serverOpts...)
	servicemanagerv1.RegisterServiceManagerServiceServer(grpcServer, grpcHandler)

	return &App{
		cfg:          cfg,
		dbPool:       dbPool,
		auditEmitter: auditEmitter,
		grpcServer:   grpcServer,
	}, nil
}

// Run starts the Service Manager gRPC server and blocks until ctx is canceled.
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
		log.Printf("servicemanager gRPC service listening on %s", a.cfg.GRPCAddr)
		if err := a.grpcServer.Serve(lis); err != nil && !errors.Is(err, grpc.ErrServerStopped) {
			errChan <- err
		}
		close(errChan)
	}()

	select {
	case <-ctx.Done():
		log.Println("shutting down servicemanager gRPC service gracefully...")
		stopped := make(chan struct{})
		go func() {
			a.grpcServer.GracefulStop()
			close(stopped)
		}()
		select {
		case <-stopped:
			log.Println("servicemanager gRPC service stopped successfully")
		case <-time.After(10 * time.Second):
			log.Println("servicemanager gRPC graceful shutdown timed out, forcing stop")
			a.grpcServer.Stop()
		}
		return nil
	case err := <-errChan:
		return err
	}
}
