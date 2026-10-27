package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/skxm03/kr0n-backend/control-plane/internal/auth"
	"github.com/skxm03/kr0n-backend/control-plane/internal/auth/config"
	"github.com/skxm03/kr0n-backend/control-plane/internal/auth/migrations"
	"github.com/skxm03/kr0n-backend/control-plane/internal/database"
)

func main() {
	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("auth config error: %v", err)
	}

	if len(os.Args) > 1 && os.Args[1] == "migrate" {
		if err := database.RunMigrationCLI(cfg.DatabaseURL, migrations.FS, os.Args[2:]); err != nil {
			log.Fatalf("auth migration error: %v", err)
		}
		return
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	app, err := auth.NewApp(ctx, cfg)
	if err != nil {
		log.Fatalf("auth init error: %v", err)
	}

	if err := app.Run(ctx); err != nil {
		log.Fatalf("auth service error: %v", err)
	}
	log.Println("auth service stopped cleanly")
}
