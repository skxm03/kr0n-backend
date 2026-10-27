package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/skxm03/kr0n-backend/control-plane/internal/gateway"
	"github.com/skxm03/kr0n-backend/control-plane/internal/gateway/config"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("gateway config error: %v", err)
	}

	app, err := gateway.NewApp(cfg)
	if err != nil {
		log.Fatalf("gateway init error: %v", err)
	}

	if err := app.Run(ctx); err != nil {
		log.Fatalf("gateway service error: %v", err)
	}
	log.Println("gateway service stopped cleanly")
}
