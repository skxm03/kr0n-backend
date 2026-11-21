package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/skxm03/kr0n-backend/control-plane/internal/secrets"
	"github.com/skxm03/kr0n-backend/control-plane/internal/secrets/config"
)

func main() {
	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("secrets config error: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	app, err := secrets.NewApp(ctx, cfg)
	if err != nil {
		log.Fatalf("secrets init error: %v", err)
	}

	if err := app.Run(ctx); err != nil {
		log.Fatalf("secrets runtime error: %v", err)
	}
	log.Println("secrets service stopped cleanly")
}
