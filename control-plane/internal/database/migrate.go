package database

import (
	"database/sql"
	"fmt"
	"io/fs"
	"log"
	"strconv"
	"strings"

	"github.com/golang-migrate/migrate/v4"
	pgxmigrate "github.com/golang-migrate/migrate/v4/database/pgx/v5"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/skxm03/kr0n-backend/control-plane/migrations"
)

// NewMigrator builds a golang-migrate instance over the embedded migration set. The returned
// func releases the source and database handles.
func NewMigrator(databaseURL string) (*migrate.Migrate, func(), error) {
	db, err := sql.Open("pgx/v5", databaseURL)
	if err != nil {
		return nil, nil, fmt.Errorf("open database: %w", err)
	}

	driver, err := pgxmigrate.WithInstance(db, &pgxmigrate.Config{})
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

// LatestMigrationVersion returns the highest version in the embedded migration set.
func LatestMigrationVersion() (uint, error) {
	entries, err := fs.ReadDir(migrations.FS, ".")
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
