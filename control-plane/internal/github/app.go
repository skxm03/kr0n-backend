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

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	authv1 "github.com/skxm03/kr0n-backend/control-plane/gen/auth/v1"
	githubv1 "github.com/skxm03/kr0n-backend/control-plane/gen/github/v1"
	"github.com/skxm03/kr0n-backend/control-plane/internal/github/client"
	"github.com/skxm03/kr0n-backend/control-plane/internal/github/config"
	"github.com/skxm03/kr0n-backend/control-plane/internal/github/handlers"
	"github.com/skxm03/kr0n-backend/control-plane/internal/github/service"
)

// App manages the GitHub microservice lifecycle and dependencies.
type App struct {
	cfg        *config.Config
	authConn   *grpc.ClientConn
	grpcServer *grpc.Server
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

	authClient := authv1.NewAuthServiceClient(authConn)
	ghClient := client.NewHTTPClient(
		cfg.GitHubAPIURL,
		client.WithCacheTTL(cfg.CacheTTL),
		client.WithMaxResponseBytes(cfg.MaxResponseBytes),
	)

	svc := service.NewService(authClient, ghClient)
	handler := handlers.NewServer(svc)

	var serverOpts []grpc.ServerOption
	if cfg.TLSEnabled {
		cert, err := tls.LoadX509KeyPair(cfg.TLSCertFile, cfg.TLSKeyFile)
		if err != nil {
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
				_ = authConn.Close()
				return nil, fmt.Errorf("read ca cert file: %w", err)
			}
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(caPEM) {
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

	grpcServer := grpc.NewServer(serverOpts...)
	githubv1.RegisterGitHubServiceServer(grpcServer, handler)

	return &App{
		cfg:        cfg,
		authConn:   authConn,
		grpcServer: grpcServer,
	}, nil
}

// Run listens and serves incoming gRPC traffic until ctx is canceled.
func (a *App) Run(ctx context.Context) error {
	defer a.authConn.Close()

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
