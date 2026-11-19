package auth

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	authv1 "github.com/skxm03/kr0n-backend/control-plane/gen/auth/v1"
	"github.com/skxm03/kr0n-backend/control-plane/internal/auth/config"
	"github.com/skxm03/kr0n-backend/control-plane/internal/auth/handlers"
	"github.com/skxm03/kr0n-backend/control-plane/internal/auth/jwtkeys"
	"github.com/skxm03/kr0n-backend/control-plane/internal/auth/oauth"
	"github.com/skxm03/kr0n-backend/control-plane/internal/auth/outbox"
	"github.com/skxm03/kr0n-backend/control-plane/internal/auth/repository"
	"github.com/skxm03/kr0n-backend/control-plane/internal/auth/service"
	"github.com/skxm03/kr0n-backend/control-plane/internal/database"
	"github.com/skxm03/kr0n-backend/control-plane/internal/email"
)

// App encapsulates the Auth gRPC service dependencies and lifecycle.
type App struct {
	cfg          *config.Config
	dbPool       *pgxpool.Pool
	rmqSender    *email.RabbitMQSender
	outboxWorker *outbox.Worker
	grpcServer   *grpc.Server
}

// NewApp wires repositories, domain services, and the gRPC server for the Auth service.
func NewApp(ctx context.Context, cfg *config.Config) (*App, error) {
	dbPool, err := database.NewPostgresPool(ctx, cfg.DatabaseURL)
	if err != nil {
		return nil, err
	}

	type unifiedEmailSender interface {
		service.EmailSender
		service.InviteEmailSender
	}
	var emailSender unifiedEmailSender = email.NewLogSender(nil)
	var rmqSender *email.RabbitMQSender
	if cfg.RabbitMQURL != "" {
		rmqSender, err = email.NewRabbitMQSender(cfg.RabbitMQURL, cfg.EmailQueueName)
		if err != nil {
			dbPool.Close()
			return nil, fmt.Errorf("connect rabbitmq email sender: %w", err)
		}
		emailSender = rmqSender
	}

	outboxRepo := repository.NewPostgresOutboxRepository(dbPool)
	outboxPublisher := outbox.NewEmailPublisher(emailSender)
	outboxWorker := outbox.NewWorker(outboxRepo, outboxPublisher, outbox.DefaultConfig())

	userRepo := repository.NewPostgresUserRepository(dbPool)
	hasher := service.NewBcryptHasher(12)
	userService := service.NewUserService(
		userRepo,
		hasher,
		service.WithEmailSender(emailSender),
		service.WithOutboxNotifier(outboxWorker),
		service.WithTokenLifetime(cfg.EmailVerificationTokenLifetime),
		service.WithPasswordResetTokenLifetime(cfg.PasswordResetTokenLifetime),
		service.WithRequireVerifiedEmail(cfg.RequireVerifiedEmail),
	)

	verifRepo := repository.NewPostgresVerificationRepository(dbPool)
	verifService := service.NewVerificationService(verifRepo)

	cleanup := func() {
		if rmqSender != nil {
			_ = rmqSender.Close()
		}
		dbPool.Close()
	}

	jwtPrivateKey := jwtkeys.DevPrivateKey()
	if cfg.JWTPrivateKey != "" {
		jwtPrivateKey, err = jwtkeys.ParsePrivateKey(cfg.JWTPrivateKey)
		if err != nil {
			cleanup()
			return nil, fmt.Errorf("invalid JWT_PRIVATE_KEY: %w", err)
		}
	}

	jwtSigner, err := jwtkeys.NewSigner(jwtPrivateKey, cfg.JWTKeyID, cfg.JWTIssuer, cfg.JWTAudience, cfg.AccessTokenLifetime)
	if err != nil {
		cleanup()
		return nil, err
	}
	tokenIssuer := service.NewDefaultTokenIssuer(jwtSigner)
	sessionRepo := repository.NewPostgresSessionRepository(dbPool)
	sessionService := service.NewSessionService(userService, sessionRepo, tokenIssuer, cfg.RefreshTokenLifetime)

	githubOAuth := oauth.NewGitHubProvider(oauth.GitHubConfig{
		ClientID:     cfg.GitHubClientID,
		ClientSecret: cfg.GitHubClientSecret,
		RedirectURL:  cfg.GitHubRedirectURL,
	})

	githubApp, err := oauth.NewGitHubAppProvider(oauth.GitHubAppConfig{
		AppID:         cfg.GitHubAppID,
		AppSlug:       cfg.GitHubAppSlug,
		PrivateKeyPEM: cfg.GitHubAppPrivateKey,
		StateSecret:   cfg.GitHubAppStateSecret,
	})
	if err != nil {
		cleanup()
		return nil, fmt.Errorf("configure github app provider: %w", err)
	}

	orgRepo := repository.NewPostgresOrgRepository(dbPool)
	orgService := service.NewOrgService(
		orgRepo,
		service.WithInviteEmailSender(emailSender),
		service.WithOrgOutboxNotifier(outboxWorker),
		service.WithGitHubApp(githubApp),
	)

	auditRepo := repository.NewPostgresAuditRepository(dbPool)
	auditService := service.NewAuditService(auditRepo)

	isDev := cfg.Env == "dev" || cfg.Env == "development"
	serviceAuthConfig := handlers.ServiceAuthConfig{
		Enabled:            !isDev || cfg.AuthGRPCClientCAFile != "",
		RequireClientCert:  !isDev || cfg.AuthGRPCClientCAFile != "",
		AllowedClientNames: cfg.AuthGRPCAllowedClients,
		AllowInsecureDev:   isDev && cfg.AuthGRPCClientCAFile == "",
	}

	grpcHandler := handlers.NewServer(
		userService,
		sessionService,
		handlers.WithVerificationService(verifService),
		handlers.WithJWKS(jwtSigner.PublicJWK()),
		handlers.WithGitHubOAuth(githubOAuth),
		handlers.WithOrgService(orgService),
		handlers.WithAuditService(auditService),
		handlers.WithServiceAuthConfig(serviceAuthConfig),
	)

	var serverOpts []grpc.ServerOption
	if cfg.AuthGRPCTLSCertFile != "" && cfg.AuthGRPCTLSKeyFile != "" {
		cert, err := tls.LoadX509KeyPair(cfg.AuthGRPCTLSCertFile, cfg.AuthGRPCTLSKeyFile)
		if err != nil {
			cleanup()
			return nil, fmt.Errorf("load auth server cert/key: %w", err)
		}
		tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		}
		if cfg.AuthGRPCClientCAFile != "" {
			caPEM, err := os.ReadFile(cfg.AuthGRPCClientCAFile)
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

	serverOpts = append(serverOpts, grpc.UnaryInterceptor(handlers.NewServiceAuthInterceptor(serviceAuthConfig)))

	grpcServer := grpc.NewServer(serverOpts...)
	authv1.RegisterAuthServiceServer(grpcServer, grpcHandler)

	return &App{
		cfg:          cfg,
		dbPool:       dbPool,
		rmqSender:    rmqSender,
		outboxWorker: outboxWorker,
		grpcServer:   grpcServer,
	}, nil
}

// Run starts the gRPC server and outbox background worker, and blocks until ctx is canceled or the server fails.
func (a *App) Run(ctx context.Context) error {
	defer a.dbPool.Close()
	if a.rmqSender != nil {
		defer a.rmqSender.Close()
	}

	workerCtx, cancelWorker := context.WithCancel(ctx)
	defer cancelWorker()

	go func() {
		log.Println("auth outbox background worker starting...")
		if err := a.outboxWorker.Start(workerCtx); err != nil && !errors.Is(err, context.Canceled) {
			log.Printf("auth outbox background worker error: %v", err)
		}
		log.Println("auth outbox background worker stopped")
	}()

	lis, err := net.Listen("tcp", a.cfg.AuthGRPCAddr)
	if err != nil {
		return err
	}
	defer lis.Close()

	errChan := make(chan error, 1)
	go func() {
		log.Printf("auth gRPC service listening on %s", a.cfg.AuthGRPCAddr)
		if err := a.grpcServer.Serve(lis); err != nil && !errors.Is(err, grpc.ErrServerStopped) {
			errChan <- err
		}
		close(errChan)
	}()

	select {
	case <-ctx.Done():
		log.Println("shutting down auth gRPC service gracefully...")
		stopped := make(chan struct{})
		go func() {
			a.grpcServer.GracefulStop()
			close(stopped)
		}()

		select {
		case <-stopped:
			log.Println("auth gRPC service stopped successfully")
		case <-time.After(10 * time.Second):
			log.Println("auth gRPC graceful shutdown timed out, forcing stop")
			a.grpcServer.Stop()
		}
		return nil
	case err := <-errChan:
		return err
	}
}
