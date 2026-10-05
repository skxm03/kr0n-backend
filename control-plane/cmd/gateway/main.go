package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	authv1 "github.com/skxm03/kr0n-backend/control-plane/gen/auth/v1"
	"github.com/skxm03/kr0n-backend/control-plane/internal/config"
	"github.com/skxm03/kr0n-backend/control-plane/internal/gateway"
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

	authConn, err := grpc.NewClient(cfg.AuthGRPCAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return err
	}
	defer authConn.Close()

	authClient := authv1.NewAuthServiceClient(authConn)
	handler := gateway.NewHandler(authClient)
	router := gateway.NewRouter(handler)

	server := &http.Server{
		Addr:              cfg.GatewayHTTPAddr,
		Handler:           router,
		ReadHeaderTimeout: 5 * time.Second,
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