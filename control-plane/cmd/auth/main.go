package main

import (
	"context"
	"errors"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"google.golang.org/grpc"

	authv1 "github.com/skxm03/kr0n-backend/control-plane/gen/auth/v1"
	"github.com/skxm03/kr0n-backend/control-plane/internal/auth/session"
	authgrpc "github.com/skxm03/kr0n-backend/control-plane/internal/auth/transport/grpc"
	"github.com/skxm03/kr0n-backend/control-plane/internal/auth/user"
	"github.com/skxm03/kr0n-backend/control-plane/internal/config"
	"github.com/skxm03/kr0n-backend/control-plane/internal/database"
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

	userRepo := user.NewPostgresRepository(dbPool)
	hasher := user.NewBcryptHasher(12)
	userService := user.NewService(userRepo, hasher)

	jwtSigner, err := session.NewJWTSigner([]byte(cfg.JWTSigningKey), cfg.JWTIssuer, cfg.AccessTokenLifetime)
	if err != nil {
		return err
	}
	tokenIssuer := session.NewDefaultTokenIssuer(jwtSigner)
	sessionRepo := session.NewPostgresRepository(dbPool)
	sessionService := session.NewService(userService, sessionRepo, tokenIssuer, cfg.RefreshTokenLifetime)

	grpcHandler := authgrpc.NewServer(userService, sessionService)

	grpcServer := grpc.NewServer()
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