package main

import (
	"fmt"
	"io/fs"
	"log"
	"os"

	authconfig "github.com/skxm03/kr0n-backend/control-plane/internal/auth/config"
	authmigrations "github.com/skxm03/kr0n-backend/control-plane/internal/auth/migrations"
	"github.com/skxm03/kr0n-backend/control-plane/internal/database"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	service := "auth"
	args := os.Args[1:]

	switch args[0] {
	case "auth":
		service = args[0]
		args = args[1:]
	case "up", "down", "version", "force":
		// Default to "auth" when service name is omitted for backward compatibility.
	default:
		printUsage()
		os.Exit(1)
	}

	if len(args) < 1 {
		printUsage()
		os.Exit(1)
	}

	var (
		dbURL        string
		migrationsFS fs.FS
	)

	switch service {
	case "auth":
		cfg, err := authconfig.LoadConfig()
		if err != nil {
			log.Fatalf("failed to load %s configuration: %v", service, err)
		}
		dbURL = cfg.DatabaseURL
		migrationsFS = authmigrations.FS
	default:
		log.Fatalf("unknown service %q", service)
	}

	if err := database.RunMigrationCLI(dbURL, migrationsFS, args); err != nil {
		log.Fatal(err)
	}
}

func printUsage() {
	fmt.Println(`Usage: migrate [service] <command> [arguments]

Services:
  auth           Run migrations for the auth service (default if omitted)

Commands:
  up             Apply all pending migrations
  down           Revert the most recent migration step
  version        Print current migration version and dirty status
  force <ver>    Set migration version cleanly and clear dirty state`)
}
