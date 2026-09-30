package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/skxm03/kr0n-backend/control-plane/internal/config"
	"github.com/skxm03/kr0n-backend/control-plane/internal/database"
)

func main() {
	if err := run(); err != nil {
		log.Printf("PostgreSQL verification failed: %v", err)
		os.Exit(1)
	}
	log.Println("PostgreSQL verification succeeded")
}

func run() error {
	log.Println("Loading configuration...")
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	log.Println("Connecting to PostgreSQL pool...")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	pool, err := database.NewPostgresPool(ctx, cfg.DatabaseURL)
	if err != nil {
		return fmt.Errorf("connect to database: %w", err)
	}
	defer func() {
		log.Println("Closing PostgreSQL pool...")
		pool.Close()
	}()

	log.Println("Pinging PostgreSQL...")
	if err := pool.Ping(ctx); err != nil {
		return fmt.Errorf("ping database: %w", err)
	}

	log.Println("Successfully connected and pinged PostgreSQL")
	return nil
}
