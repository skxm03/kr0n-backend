package github

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

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	authv1 "github.com/skxm03/kr0n-backend/control-plane/gen/auth/v1"
	githubv1 "github.com/skxm03/kr0n-backend/control-plane/gen/github/v1"
	"github.com/skxm03/kr0n-backend/control-plane/internal/github/client"
	"github.com/skxm03/kr0n-backend/control-plane/internal/github/config"
	"github.com/skxm03/kr0n-backend/control-plane/internal/github/handlers"
	"github.com/skxm03/kr0n-backend/control-plane/internal/github/provider"
	"github.com/skxm03/kr0n-backend/control-plane/internal/github/repository"
	"github.com/skxm03/kr0n-backend/control-plane/internal/github/service"
	"github.com/skxm03/kr0n-backend/control-plane/internal/github/webhook"
	pkgAudit "github.com/skxm03/kr0n-backend/control-plane/pkg/audit"
)

// App manages the GitHub microservice lifecycle and dependencies.
type App struct {
	cfg          *config.Config
	dbPool       *pgxpool.Pool
	authConn     *grpc.ClientConn
	auditEmitter pkgAudit.Emitter
	grpcServer   *grpc.Server
}

type authAuthorizer struct {
	client authv1.AuthServiceClient
}

func (a *authAuthorizer) CheckPermission(ctx context.Context, caller *authv1.CallerPrincipal, orgID, permission string) (bool, error) {
	resp, err := a.client.CheckPermission(ctx, &authv1.CheckPermissionRequest{
		Caller:     caller,
		OrgId:      orgID,
		Permission: permission,
	})
	if err != nil {
		return false, err
	}
	return resp.GetAllowed(), nil
}

type auditEmitterAdapter struct {
	emitter pkgAudit.Emitter
}

func (a *auditEmitterAdapter) Record(ctx context.Context, orgID, action, resourceType, resourceID string, meta map[string]any) error {
	if a == nil || a.emitter == nil {
		return nil
	}
	var orgUUID *uuid.UUID
	if id, err := uuid.Parse(orgID); err == nil {
		orgUUID = &id
	}
	ev := pkgAudit.Event{
		Service:        "github",
		Action:         action,
		Status:         pkgAudit.StatusSuccess,
		OrganizationID: orgUUID,
		Actor: pkgAudit.Actor{
			Type: "system",
		},
		Target: pkgAudit.Target{
			Type: resourceType,
			ID:   resourceID,
		},
		Metadata:  meta,
		Timestamp: time.Now().UTC(),
	}
	ev.Normalize("github")
	return a.emitter.Emit(ctx, ev)
}

// NewApp initializes dependencies, Auth Service gRPC client, GitHub REST client, and gRPC server.
func NewApp(ctx context.Context, cfg *config.Config) (*App, error) {
	authDialOpts, err := buildAuthDialOptions(cfg)
	if err != nil {
		return nil, fmt.Errorf("build auth dial options: %w", err)
	}

	authConn, err := grpc.DialContext(ctx, cfg.AuthGRPCAddr, authDialOpts...)
	if err != nil {
		return nil, fmt.Errorf("dial auth service (%s): %w", cfg.AuthGRPCAddr, err)
	}

	var dbPool *pgxpool.Pool
	if cfg.DatabaseURL != "" {
		pool, err := pgxpool.New(ctx, cfg.DatabaseURL)
		if err != nil {
			_ = authConn.Close()
			return nil, fmt.Errorf("connect github database pool: %w", err)
		}
		dbPool = pool
	}

	var instRepo repository.InstallationRepository
	if dbPool != nil {
		instRepo = repository.NewPostgresInstallationRepository(dbPool)
	}

	privKeyPEM := cfg.GitHubAppPrivateKey
	if privKeyPEM == "" {
		privKeyPEM = cfg.GitHubAppPrivateKeyPath
	}

	ghApp, err := provider.NewGitHubAppProvider(provider.GitHubAppConfig{
		AppID:         cfg.GitHubAppID,
		AppSlug:       cfg.GitHubAppSlug,
		PrivateKeyPEM: privKeyPEM,
		StateSecret:   cfg.GitHubAppStateSecret,
		APIURL:        cfg.GitHubAPIURL,
	})
	if err != nil {
		if dbPool != nil {
			dbPool.Close()
		}
		_ = authConn.Close()
		return nil, fmt.Errorf("configure github app provider: %w", err)
	}

	authClient := authv1.NewAuthServiceClient(authConn)
	authorizer := &authAuthorizer{client: authClient}

	ghClient := client.NewHTTPClient(
		cfg.GitHubAPIURL,
		client.WithCacheTTL(cfg.CacheTTL),
		client.WithMaxResponseBytes(cfg.MaxResponseBytes),
	)

	svc := service.NewService(
		service.WithAuthorizer(authorizer),
		service.WithGitHubApp(ghApp),
		service.WithInstallationRepository(instRepo),
		service.WithGitHubClient(ghClient),
	)

	var auditEmitter pkgAudit.Emitter
	if cfg.AuditRabbitMQURL != "" {
		emitter, err := pkgAudit.NewRabbitMQEmitter(pkgAudit.EmitterConfig{
			AMQPURL:      cfg.AuditRabbitMQURL,
			ServiceName:  "github",
			ExchangeName: cfg.AuditExchangeName,
		})
		if err != nil {
			if dbPool != nil {
				dbPool.Close()
			}
			_ = authConn.Close()
			return nil, fmt.Errorf("connect github audit rabbitmq emitter: %w", err)
		}
		auditEmitter = emitter
	}

	webhookHandler := webhook.NewWebhookHandler(
		cfg.GitHubWebhookSecret,
		cfg.GitHubWebhookMaxBytes,
		svc,
		&auditEmitterAdapter{emitter: auditEmitter},
	)
	service.WithWebhookHandler(webhookHandler)(svc)

	handler := handlers.NewServer(svc)

	var serverOpts []grpc.ServerOption
	if cfg.TLSEnabled {
		cert, err := tls.LoadX509KeyPair(cfg.TLSCertFile, cfg.TLSKeyFile)
		if err != nil {
			if dbPool != nil {
				dbPool.Close()
			}
			_ = authConn.Close()
			return nil, fmt.Errorf("load server tls cert/key: %w", err)
		}
		tlsCfg := &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		}
		if cfg.TLSCAFile != "" {
			caPEM, err := os.ReadFile(cfg.TLSCAFile)
			if err != nil {
				if dbPool != nil {
					dbPool.Close()
				}
				_ = authConn.Close()
				return nil, fmt.Errorf("read ca cert file: %w", err)
			}
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(caPEM) {
				if dbPool != nil {
					dbPool.Close()
				}
				_ = authConn.Close()
				return nil, errors.New("ca file contains no valid certificates")
			}
			tlsCfg.ClientCAs = pool
			if cfg.TLSClientAuth {
				tlsCfg.ClientAuth = tls.RequireAndVerifyClientCert
			}
		}
		serverOpts = append(serverOpts, grpc.Creds(credentials.NewTLS(tlsCfg)))
	}

	if auditEmitter != nil {
		serverOpts = append(serverOpts, grpc.UnaryInterceptor(pkgAudit.UnaryServerInterceptor(auditEmitter, "github", nil)))
	}

	grpcServer := grpc.NewServer(serverOpts...)
	githubv1.RegisterGitHubServiceServer(grpcServer, handler)

	return &App{
		cfg:          cfg,
		dbPool:       dbPool,
		authConn:     authConn,
		auditEmitter: auditEmitter,
		grpcServer:   grpcServer,
	}, nil
}

// Run listens and serves incoming gRPC traffic until ctx is canceled.
func (a *App) Run(ctx context.Context) error {
	defer a.authConn.Close()
	if a.dbPool != nil {
		defer a.dbPool.Close()
	}
	if a.auditEmitter != nil {
		defer a.auditEmitter.Close()
	}

	addr := ":" + a.cfg.GRPCPort
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", addr, err)
	}

	errCh := make(chan error, 1)
	go func() {
		log.Printf("github microservice listening on %s", addr)
		if err := a.grpcServer.Serve(lis); err != nil && !errors.Is(err, grpc.ErrServerStopped) {
			errCh <- err
		}
		close(errCh)
	}()

	select {
	case <-ctx.Done():
		log.Println("shutting down github microservice...")
		a.grpcServer.GracefulStop()
		return nil
	case err := <-errCh:
		return err
	}
}

func buildAuthDialOptions(cfg *config.Config) ([]grpc.DialOption, error) {
	if cfg.TLSEnabled {
		tlsCfg := &tls.Config{
			MinVersion: tls.VersionTLS12,
		}
		if cfg.TLSCAFile != "" {
			caPEM, err := os.ReadFile(cfg.TLSCAFile)
			if err != nil {
				return nil, fmt.Errorf("read ca cert file: %w", err)
			}
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(caPEM) {
				return nil, errors.New("ca file contains no valid certificates")
			}
			tlsCfg.RootCAs = pool
		}
		if cfg.TLSCertFile != "" && cfg.TLSKeyFile != "" {
			clientCert, err := tls.LoadX509KeyPair(cfg.TLSCertFile, cfg.TLSKeyFile)
			if err != nil {
				return nil, fmt.Errorf("load client cert/key for auth dial: %w", err)
			}
			tlsCfg.Certificates = []tls.Certificate{clientCert}
		}
		if cfg.InsecureDevSkipVerify {
			tlsCfg.InsecureSkipVerify = true
		}
		return []grpc.DialOption{grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg))}, nil
	}

	return []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())}, nil
}
