package main

import (
	"fmt"
	"io/fs"
	"log"
	"os"

	authconfig "github.com/skxm03/kr0n-backend/control-plane/internal/auth/config"
	authmigrations "github.com/skxm03/kr0n-backend/control-plane/internal/auth/migrations"
	"github.com/skxm03/kr0n-backend/control-plane/internal/database"
	secretsconfig "github.com/skxm03/kr0n-backend/control-plane/internal/secrets/config"
	secretsmigrations "github.com/skxm03/kr0n-backend/control-plane/internal/secrets/migrations"
	smconfig "github.com/skxm03/kr0n-backend/control-plane/internal/servicemanager/config"
	smmigrations "github.com/skxm03/kr0n-backend/control-plane/internal/servicemanager/migrations"
)

type migrationTarget struct {
	Name            string
	DatabaseURL     string
	FS              fs.FS
	MigrationsTable string
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	service := "all"
	args := os.Args[1:]

	switch args[0] {
	case "auth", "servicemanager", "secrets", "all":
		service = args[0]
		args = args[1:]
	case "up", "down", "version", "force":
		// Default to "all" when service name is omitted.
	default:
		printUsage()
		os.Exit(1)
	}

	if len(args) < 1 {
		printUsage()
		os.Exit(1)
	}

	targets, err := resolveTargets(service)
	if err != nil {
		log.Fatalf("resolve migration targets: %v", err)
	}

	for _, t := range targets {
		log.Printf("==> Executing %s migrations on %s (table: %s)", args[0], t.Name, t.MigrationsTable)
		if err := database.RunMigrationCLIWithTable(t.DatabaseURL, t.FS, t.MigrationsTable, args); err != nil {
			log.Fatalf("failed migration for %s: %v", t.Name, err)
		}
	}
}

func resolveTargets(service string) ([]migrationTarget, error) {
	switch service {
	case "auth":
		cfg, err := authconfig.LoadConfig()
		if err != nil {
			return nil, fmt.Errorf("load auth config: %w", err)
		}
		return []migrationTarget{
			{
				Name:            "auth",
				DatabaseURL:     cfg.DatabaseURL,
				FS:              authmigrations.FS,
				MigrationsTable: "schema_migrations_auth",
			},
		}, nil

	case "servicemanager":
		cfg, err := smconfig.LoadConfig()
		if err != nil {
			return nil, fmt.Errorf("load servicemanager config: %w", err)
		}
		return []migrationTarget{
			{
				Name:            "servicemanager",
				DatabaseURL:     cfg.DatabaseURL,
				FS:              smmigrations.FS,
				MigrationsTable: "schema_migrations_servicemanager",
			},
		}, nil

	case "secrets":
		cfg, err := secretsconfig.LoadConfig()
		if err != nil {
			return nil, fmt.Errorf("load secrets config: %w", err)
		}
		return []migrationTarget{
			{
				Name:            "secrets",
				DatabaseURL:     cfg.DatabaseURL,
				FS:              secretsmigrations.FS,
				MigrationsTable: "schema_migrations_secrets",
			},
		}, nil

	case "all":
		authCfg, err := authconfig.LoadConfig()
		if err != nil {
			return nil, fmt.Errorf("load auth config: %w", err)
		}
		smCfg, err := smconfig.LoadConfig()
		if err != nil {
			return nil, fmt.Errorf("load servicemanager config: %w", err)
		}
		secCfg, err := secretsconfig.LoadConfig()
		if err != nil {
			return nil, fmt.Errorf("load secrets config: %w", err)
		}

		return []migrationTarget{
			{
				Name:            "auth",
				DatabaseURL:     authCfg.DatabaseURL,
				FS:              authmigrations.FS,
				MigrationsTable: "schema_migrations_auth",
			},
			{
				Name:            "servicemanager",
				DatabaseURL:     smCfg.DatabaseURL,
				FS:              smmigrations.FS,
				MigrationsTable: "schema_migrations_servicemanager",
			},
			{
				Name:            "secrets",
				DatabaseURL:     secCfg.DatabaseURL,
				FS:              secretsmigrations.FS,
				MigrationsTable: "schema_migrations_secrets",
			},
		}, nil

	default:
		return nil, fmt.Errorf("unknown service %q", service)
	}
}

func printUsage() {
	fmt.Println(`Usage: migrate [service] <command> [arguments]

Services:
  all            Run migrations for all microservices in order (default if omitted)
  auth           Run migrations for the auth service
  servicemanager Run migrations for the service manager
  secrets        Run migrations for the secrets service

Commands:
  up             Apply all pending migrations
  down           Revert the most recent migration step
  version        Print current migration version and dirty status
  force <ver>    Set migration version cleanly and clear dirty state`)
}
