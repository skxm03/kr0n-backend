package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/skxm03/kr0n-backend/control-plane/internal/github"
	"github.com/skxm03/kr0n-backend/control-plane/internal/github/config"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("github config error: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	app, err := github.NewApp(ctx, cfg)
	if err != nil {
		log.Fatalf("github init error: %v", err)
	}

	if err := app.Run(ctx); err != nil {
		log.Fatalf("github service error: %v", err)
	}
	log.Println("github service stopped cleanly")
}
