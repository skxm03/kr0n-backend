package database

import (
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"strconv"
	"strings"

	"github.com/golang-migrate/migrate/v4"
	pgxmigrate "github.com/golang-migrate/migrate/v4/database/pgx/v5"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	_ "github.com/jackc/pgx/v5/stdlib"
)

// NewMigrator builds a golang-migrate instance over the provided migration filesystem.
// The returned func releases the source and database handles.
func NewMigrator(databaseURL string, migrationsFS fs.FS) (*migrate.Migrate, func(), error) {
	db, err := sql.Open("pgx/v5", databaseURL)
	if err != nil {
		return nil, nil, fmt.Errorf("open database: %w", err)
	}

	driver, err := pgxmigrate.WithInstance(db, &pgxmigrate.Config{})
	if err != nil {
		db.Close()
		return nil, nil, fmt.Errorf("create pgx migration driver: %w", err)
	}

	sourceDriver, err := iofs.New(migrationsFS, ".")
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

// LatestMigrationVersion returns the highest version in the provided migration filesystem.
func LatestMigrationVersion(migrationsFS fs.FS) (uint, error) {
	entries, err := fs.ReadDir(migrationsFS, ".")
	if err != nil {
		return 0, fmt.Errorf("read embedded migrations: %w", err)
	}
	var latest uint
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".up.sql") {
			continue
		}
		prefix, _, ok := strings.Cut(name, "_")
		if !ok {
			continue
		}
		v, err := strconv.ParseUint(prefix, 10, 32)
		if err != nil {
			return 0, fmt.Errorf("parse migration version from %q: %w", name, err)
		}
		if uint(v) > latest {
			latest = uint(v)
		}
	}
	if latest == 0 {
		return 0, fmt.Errorf("no migrations embedded")
	}
	return latest, nil
}

// RunMigrationCLI executes a migration command ("up", "down", "version", or "force <ver>")
// against databaseURL using migrationsFS.
func RunMigrationCLI(databaseURL string, migrationsFS fs.FS, args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("missing migration command (expected: up, down, version, force <ver>)")
	}

	m, closeFn, err := NewMigrator(databaseURL, migrationsFS)
	if err != nil {
		return fmt.Errorf("initialize migrator: %w", err)
	}
	defer closeFn()

	switch args[0] {
	case "up":
		if err := m.Up(); err != nil {
			if errors.Is(err, migrate.ErrNoChange) {
				log.Println("migrations: no change (schema is up to date)")
				return nil
			}
			return fmt.Errorf("migration up failed: %w", err)
		}
		log.Println("migration up succeeded")
		return nil

	case "down":
		if err := m.Steps(-1); err != nil {
			if errors.Is(err, migrate.ErrNoChange) {
				log.Println("migrations: no change (no migrations to revert)")
				return nil
			}
			return fmt.Errorf("migration down failed: %w", err)
		}
		log.Println("migration down succeeded (reverted 1 step)")
		return nil

	case "version":
		version, dirty, err := m.Version()
		if err != nil {
			if errors.Is(err, migrate.ErrNilVersion) {
				log.Println("migrations: no migrations applied yet (version: nil)")
				return nil
			}
			return fmt.Errorf("read migration version: %w", err)
		}
		log.Printf("current migration version: %d (dirty: %t)", version, dirty)
		return nil

	case "force":
		if len(args) < 2 {
			return fmt.Errorf("missing version argument for force command (usage: force <version>)")
		}
		version, err := strconv.Atoi(args[1])
		if err != nil {
			return fmt.Errorf("invalid version argument %q: %w", args[1], err)
		}
		if err := m.Force(version); err != nil {
			return fmt.Errorf("migration force failed: %w", err)
		}
		log.Printf("migration version successfully forced to: %d", version)
		return nil

	default:
		return fmt.Errorf("unknown migration command %q (expected: up, down, version, force <ver>)", args[0])
	}
}
