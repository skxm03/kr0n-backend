package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	authv1 "github.com/skxm03/kr0n-backend/control-plane/gen/auth/v1"
	"github.com/skxm03/kr0n-backend/control-plane/internal/auth/audit"
	"github.com/skxm03/kr0n-backend/control-plane/internal/auth/jwtkeys"
	"github.com/skxm03/kr0n-backend/control-plane/internal/auth/oauth"
	"github.com/skxm03/kr0n-backend/control-plane/internal/auth/org"
	"github.com/skxm03/kr0n-backend/control-plane/internal/auth/session"
	authgrpc "github.com/skxm03/kr0n-backend/control-plane/internal/auth/transport/grpc"
	"github.com/skxm03/kr0n-backend/control-plane/internal/auth/user"
	"github.com/skxm03/kr0n-backend/control-plane/internal/auth/verification"
	"github.com/skxm03/kr0n-backend/control-plane/internal/config"
	"github.com/skxm03/kr0n-backend/control-plane/internal/database"
	"github.com/skxm03/kr0n-backend/control-plane/internal/email"
)

func main() {
	if err := run(); err != nil {
		log.Printf("auth service error: %v", err)
		os.Exit(1)
	}
	log.Println("auth service stopped cleanly")
}

func run() error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cfg, err := config.Load()
	if err != nil {
		return err
	}

	dbPool, err := database.NewPostgresPool(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer dbPool.Close()

	type unifiedEmailSender interface {
		verification.EmailSender
		org.InviteEmailSender
	}
	var emailSender unifiedEmailSender = email.NewLogSender(nil)
	if cfg.SMTPAddr != "" {
		emailSender = email.NewSMTPSender(email.SMTPConfig{
			Addr:     cfg.SMTPAddr,
			From:     cfg.SMTPFrom,
			Username: cfg.SMTPUsername,
			Password: cfg.SMTPPassword,
		})
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

	jwtSigner, err := jwtkeys.NewSigner(cfg.JWTPrivateKey, cfg.JWTKeyID, cfg.JWTIssuer, cfg.JWTAudience, cfg.AccessTokenLifetime)
	if err != nil {
		return err
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

	serviceAuthConfig := authgrpc.ServiceAuthConfig{
		Enabled:            !config.IsDevEnv(cfg.Env) || cfg.AuthGRPCClientCAFile != "" || cfg.AuthServiceToken != "",
		AllowedClientNames: cfg.AuthGRPCAllowedClients,
		ServiceToken:       cfg.AuthServiceToken,
		AllowInsecureDev:   config.IsDevEnv(cfg.Env) && cfg.AuthGRPCClientCAFile == "" && cfg.AuthServiceToken == "",
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
			return fmt.Errorf("load auth server cert/key: %w", err)
		}
		tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		}
		if cfg.AuthGRPCClientCAFile != "" {
			caPEM, err := os.ReadFile(cfg.AuthGRPCClientCAFile)
			if err != nil {
				return fmt.Errorf("read client ca file: %w", err)
			}
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(caPEM) {
				return errors.New("failed to parse client ca cert")
			}
			tlsConfig.ClientCAs = pool
			tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
		}
		serverOpts = append(serverOpts, grpc.Creds(credentials.NewTLS(tlsConfig)))
	} else if cfg.Env != "dev" {
		return errors.New("plaintext gRPC is only allowed when KR0N_ENV=dev")
	}

	serverOpts = append(serverOpts, grpc.UnaryInterceptor(authgrpc.NewServiceAuthInterceptor(serviceAuthConfig)))

	grpcServer := grpc.NewServer(serverOpts...)
	authv1.RegisterAuthServiceServer(grpcServer, grpcHandler)

	lis, err := net.Listen("tcp", cfg.AuthGRPCAddr)
	if err != nil {
		return err
	}
	defer lis.Close()

	errChan := make(chan error, 1)
	go func() {
		log.Printf("auth gRPC service listening on %s", cfg.AuthGRPCAddr)
		if err := grpcServer.Serve(lis); err != nil && !errors.Is(err, grpc.ErrServerStopped) {
			errChan <- err
		}
		close(errChan)
	}()

	select {
	case <-ctx.Done():
		log.Println("shutting down auth gRPC service gracefully...")
		stopped := make(chan struct{})
		go func() {
			grpcServer.GracefulStop()
			close(stopped)
		}()

		select {
		case <-stopped:
			log.Println("auth gRPC service stopped successfully")
		case <-time.After(10 * time.Second):
			log.Println("auth gRPC graceful shutdown timed out, forcing stop")
			grpcServer.Stop()
		}
		return nil
	case err := <-errChan:
		return err
	}
}
