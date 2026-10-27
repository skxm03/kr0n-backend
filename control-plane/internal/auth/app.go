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
	"github.com/skxm03/kr0n-backend/control-plane/internal/auth/audit"
	"github.com/skxm03/kr0n-backend/control-plane/internal/auth/config"
	"github.com/skxm03/kr0n-backend/control-plane/internal/auth/jwtkeys"
	"github.com/skxm03/kr0n-backend/control-plane/internal/auth/oauth"
	"github.com/skxm03/kr0n-backend/control-plane/internal/auth/org"
	"github.com/skxm03/kr0n-backend/control-plane/internal/auth/session"
	authgrpc "github.com/skxm03/kr0n-backend/control-plane/internal/auth/transport/grpc"
	"github.com/skxm03/kr0n-backend/control-plane/internal/auth/user"
	"github.com/skxm03/kr0n-backend/control-plane/internal/auth/verification"
	"github.com/skxm03/kr0n-backend/control-plane/internal/database"
	"github.com/skxm03/kr0n-backend/control-plane/internal/email"
)

// App encapsulates the Auth gRPC service dependencies and lifecycle.
type App struct {
	cfg         *config.Config
	dbPool      *pgxpool.Pool
	rmqSender   *email.RabbitMQSender
	grpcServer  *grpc.Server
}

// NewApp wires repositories, domain services, and the gRPC server for the Auth service.
func NewApp(ctx context.Context, cfg *config.Config) (*App, error) {
	dbPool, err := database.NewPostgresPool(ctx, cfg.DatabaseURL)
	if err != nil {
		return nil, err
	}

	type unifiedEmailSender interface {
		verification.EmailSender
		org.InviteEmailSender
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

	userRepo := user.NewPostgresRepository(dbPool)
	hasher := user.NewBcryptHasher(12)
	userService := user.NewService(
		userRepo,
		hasher,
		user.WithEmailSender(emailSender),
		user.WithTokenLifetime(cfg.EmailVerificationTokenLifetime),
		user.WithPasswordResetTokenLifetime(cfg.PasswordResetTokenLifetime),
		user.WithRequireVerifiedEmail(cfg.RequireVerifiedEmail),
	)

	verifRepo := verification.NewPostgresRepository(dbPool)
	verifService := verification.NewService(verifRepo)

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
	tokenIssuer := session.NewDefaultTokenIssuer(jwtSigner)
	sessionRepo := session.NewPostgresRepository(dbPool)
	sessionService := session.NewService(userService, sessionRepo, tokenIssuer, cfg.RefreshTokenLifetime)

	githubOAuth := oauth.NewGitHubProvider(oauth.GitHubConfig{
		ClientID:     cfg.GitHubClientID,
		ClientSecret: cfg.GitHubClientSecret,
		RedirectURL:  cfg.GitHubRedirectURL,
	})

	orgRepo := org.NewPostgresRepository(dbPool)
	orgService := org.NewService(orgRepo, org.WithInviteEmailSender(emailSender))

	auditRepo := audit.NewPostgresRepository(dbPool)
	auditService := audit.NewService(auditRepo)

	isDev := cfg.Env == "dev" || cfg.Env == "development"
	serviceAuthConfig := authgrpc.ServiceAuthConfig{
		Enabled:             !isDev || cfg.AuthGRPCClientCAFile != "" || cfg.AuthServiceToken != "",
		RequireClientCert:   !isDev || cfg.AuthGRPCClientCAFile != "",
		RequireServiceToken: cfg.AuthServiceToken != "",
		AllowedClientNames:  cfg.AuthGRPCAllowedClients,
		ServiceToken:        cfg.AuthServiceToken,
		AllowInsecureDev:    isDev && cfg.AuthGRPCClientCAFile == "" && cfg.AuthServiceToken == "",
	}

	grpcHandler := authgrpc.NewServer(
		userService,
		sessionService,
		authgrpc.WithVerificationService(verifService),
		authgrpc.WithJWKS(jwtSigner.PublicJWK()),
		authgrpc.WithGitHubOAuth(githubOAuth),
		authgrpc.WithOrgService(orgService),
		authgrpc.WithAuditService(auditService),
		authgrpc.WithServiceAuthConfig(serviceAuthConfig),
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

	serverOpts = append(serverOpts, grpc.UnaryInterceptor(authgrpc.NewServiceAuthInterceptor(serviceAuthConfig)))

	grpcServer := grpc.NewServer(serverOpts...)
	authv1.RegisterAuthServiceServer(grpcServer, grpcHandler)

	return &App{
		cfg:        cfg,
		dbPool:     dbPool,
		rmqSender:  rmqSender,
		grpcServer: grpcServer,
	}, nil
}

// Run starts the gRPC server and blocks until ctx is canceled or the server fails.
func (a *App) Run(ctx context.Context) error {
	defer a.dbPool.Close()
	if a.rmqSender != nil {
		defer a.rmqSender.Close()
	}

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
