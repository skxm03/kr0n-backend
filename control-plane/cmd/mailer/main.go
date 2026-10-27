package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/skxm03/kr0n-backend/control-plane/internal/mailer"
	"github.com/skxm03/kr0n-backend/control-plane/internal/mailer/config"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("mailer config error: %v", err)
	}

	app, err := mailer.NewApp(cfg)
	if err != nil {
		log.Fatalf("mailer init error: %v", err)
	}

	if err := app.Run(ctx); err != nil {
		log.Fatalf("mailer service error: %v", err)
	}
	log.Println("mailer service stopped cleanly")
}
