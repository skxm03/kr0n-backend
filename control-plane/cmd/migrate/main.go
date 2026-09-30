package main

import (
	"database/sql"
	"errors"
	"fmt"
	"log"
	"os"
	"strconv"

	"github.com/golang-migrate/migrate/v4"
	pgx "github.com/golang-migrate/migrate/v4/database/pgx/v5"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/skxm03/kr0n-backend/control-plane/internal/config"
	"github.com/skxm03/kr0n-backend/control-plane/migrations"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	command := os.Args[1]

	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("failed to load configuration: %v", err)
	}

	m, closeFn, err := newMigrator(cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("failed to initialize migrator: %v", err)
	}
	defer closeFn()

	switch command {
	case "up":
		if err := m.Up(); err != nil {
			if errors.Is(err, migrate.ErrNoChange) {
				log.Println("migrations: no change (schema is up to date)")
				return
			}
			log.Fatalf("migration up failed: %v", err)
		}
		log.Println("migration up succeeded")

	case "down":
		if err := m.Steps(-1); err != nil {
			if errors.Is(err, migrate.ErrNoChange) {
				log.Println("migrations: no change (no migrations to revert)")
				return
			}
			log.Fatalf("migration down failed: %v", err)
		}
		log.Println("migration down succeeded (reverted 1 step)")

	case "version":
		version, dirty, err := m.Version()
		if err != nil {
			if errors.Is(err, migrate.ErrNilVersion) {
				log.Println("migrations: no migrations applied yet (version: nil)")
				return
			}
			log.Fatalf("failed to read migration version: %v", err)
		}
		log.Printf("current migration version: %d (dirty: %t)", version, dirty)

	case "force":
		if len(os.Args) < 3 {
			log.Fatal("missing version argument for force command. Usage: migrate force <version>")
		}
		version, err := strconv.Atoi(os.Args[2])
		if err != nil {
			log.Fatalf("invalid version argument %q: %v", os.Args[2], err)
		}
		if err := m.Force(version); err != nil {
			log.Fatalf("migration force failed: %v", err)
		}
		log.Printf("migration version successfully forced to: %d", version)

	default:
		printUsage()
		os.Exit(1)
	}
}

func newMigrator(databaseURL string) (*migrate.Migrate, func(), error) {
	db, err := sql.Open("pgx/v5", databaseURL)
	if err != nil {
		return nil, nil, fmt.Errorf("open database: %w", err)
	}

	driver, err := pgx.WithInstance(db, &pgx.Config{})
	if err != nil {
		db.Close()
		return nil, nil, fmt.Errorf("create pgx migration driver: %w", err)
	}

	sourceDriver, err := iofs.New(migrations.FS, ".")
	if err != nil {
		db.Close()
		return nil, nil, fmt.Errorf("create iofs source driver: %w", err)
	}

	m, err := migrate.NewWithInstance("iofs", sourceDriver, "pgx5", driver)
	if err != nil {
		db.Close()
		return nil, nil, fmt.Errorf("create migrate instance: %w", err)
	}

	closeFn := func() {
		sourceErr, dbErr := m.Close()
		if sourceErr != nil {
			log.Printf("warning: error closing migration source: %v", sourceErr)
		}
		if dbErr != nil {
			log.Printf("warning: error closing migration database: %v", dbErr)
		}
	}

	return m, closeFn, nil
}

func printUsage() {
	fmt.Println(`Usage: migrate <command> [arguments]

Commands:
  up             Apply all pending migrations
  down           Revert the most recent migration step
  version        Print current migration version and dirty status
  force <ver>    Set migration version cleanly and clear dirty state`)
}
