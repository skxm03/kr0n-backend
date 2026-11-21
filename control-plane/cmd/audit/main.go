package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/skxm03/kr0n-backend/control-plane/internal/audit"
	"github.com/skxm03/kr0n-backend/control-plane/internal/audit/config"
	"github.com/skxm03/kr0n-backend/control-plane/internal/audit/sinks"
	"github.com/skxm03/kr0n-backend/control-plane/internal/database"
)

func buildSinks(ctx context.Context, cfg *config.Config) (audit.Sink, error) {
	requested := cfg.Sinks
	if len(requested) == 0 {
		requested = []string{"postgres", "logger"}
	}

	var primary []audit.Sink
	var auxiliary []audit.Sink

	cleanup := func() {
		for _, s := range primary {
			_ = s.Close()
		}
		for _, s := range auxiliary {
			_ = s.Close()
		}
	}

	for _, raw := range requested {
		name := strings.ToLower(strings.TrimSpace(raw))
		switch name {
		case "", "none":
			continue
		case "postgres", "postgresql", "db":
			pool, err := database.NewPostgresPool(ctx, cfg.DatabaseURL)
			if err != nil {
				cleanup()
				return nil, fmt.Errorf("connect postgres audit sink: %w", err)
			}
			primary = append(primary, sinks.NewPostgresSink(pool, true))
		case "logger", "stdout", "log":
			auxiliary = append(auxiliary, sinks.NewLoggerSink(os.Stdout))
		default:
			cleanup()
			return nil, fmt.Errorf("unknown audit sink %q (supported: postgres, logger)", name)
		}
	}

	if len(primary) == 0 && len(auxiliary) == 0 {
		primary = append(primary, sinks.NewLoggerSink(os.Stdout))
	}

	return sinks.NewTieredMultiSink(primary, auxiliary), nil
}

func main() {
	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("audit worker config error: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	app, err := audit.NewApp(ctx, cfg, buildSinks)
	if err != nil {
		log.Fatalf("audit worker init error: %v", err)
	}

	if err := app.Run(ctx); err != nil {
		log.Fatalf("audit worker runtime error: %v", err)
	}
	log.Println("audit worker service stopped cleanly")
}
