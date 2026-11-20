package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/skxm03/kr0n-backend/control-plane/internal/servicemanager"
	"github.com/skxm03/kr0n-backend/control-plane/internal/servicemanager/config"
)

func main() {
	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("servicemanager config error: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	app, err := servicemanager.NewApp(ctx, cfg)
	if err != nil {
		log.Fatalf("servicemanager init error: %v", err)
	}

	if err := app.Run(ctx); err != nil {
		log.Fatalf("servicemanager runtime error: %v", err)
	}
	log.Println("servicemanager service stopped cleanly")
}
