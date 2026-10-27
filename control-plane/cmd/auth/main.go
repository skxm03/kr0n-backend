package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/skxm03/kr0n-backend/control-plane/internal/auth"
	"github.com/skxm03/kr0n-backend/control-plane/internal/auth/config"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("auth config error: %v", err)
	}

	app, err := auth.NewApp(ctx, cfg)
	if err != nil {
		log.Fatalf("auth init error: %v", err)
	}

	if err := app.Run(ctx); err != nil {
		log.Fatalf("auth service error: %v", err)
	}
	log.Println("auth service stopped cleanly")
}
