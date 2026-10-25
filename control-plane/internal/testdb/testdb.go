// Package testdb centralises how tests obtain a PostgreSQL database. Every integration and E2E
// test must go through it so that no test can ever reach the development/production database.
//
// Rules enforced here:
//   - Only TEST_DATABASE_URL is read. DATABASE_URL is never used as a fallback.
//   - The database name must contain a "test" segment (e.g. kr0n_test) and must not be the same
//     database DATABASE_URL points at.
//   - The host must be loopback unless KR0N_TEST_ALLOW_NONLOCAL_DB=1 is set explicitly.
//   - The embedded migrations are applied (fresh, partial or behind), and the resulting version
//     is verified against the latest embedded migration. Dirty or newer-than-code databases are
//     refused with instructions rather than silently repaired.
//   - Destructive migration-lifecycle tests run in a throwaway database created and dropped by
//     the test itself (NewOwnedDatabase), never in the shared test database.
package testdb

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/golang-migrate/migrate/v4"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/skxm03/kr0n-backend/control-plane/internal/database"
)

const (
	// EnvURL is the only variable that selects the integration-test database.
	EnvURL = "TEST_DATABASE_URL"
	// EnvRequire makes missing configuration a test failure instead of a skip (use in CI).
	EnvRequire = "KR0N_REQUIRE_DB_TESTS"
	// EnvAllowNonLocal permits a non-loopback test database host.
	EnvAllowNonLocal = "KR0N_TEST_ALLOW_NONLOCAL_DB"
)

var testNameSegment = regexp.MustCompile(`(^|_)test($|_)`)

// Validate returns an error unless rawURL positively identifies an isolated test database.
// devURL is the normal application DATABASE_URL (may be empty); the test URL must differ from it.
func Validate(rawURL, devURL string, allowNonLocal bool) error {
	u, err := parse(rawURL)
	if err != nil {
		return err
	}
	name := dbName(u)
	if name == "" {
		return errors.New("test database URL has no database name")
	}
	if !testNameSegment.MatchString(strings.ToLower(name)) {
		return fmt.Errorf("refusing database %q: the name must contain a \"test\" segment (e.g. kr0n_test)", name)
	}
	if !allowNonLocal && !isLoopback(u.Hostname()) {
		return fmt.Errorf("refusing non-loopback host %q (set %s=1 to override explicitly)", u.Hostname(), EnvAllowNonLocal)
	}
	if devURL != "" {
		if d, err := parse(devURL); err == nil && sameDatabase(u, d) {
			return fmt.Errorf("refusing database %q: it is the same database as DATABASE_URL", name)
		}
	}
	return nil
}

// URL returns the validated TEST_DATABASE_URL. When it is not configured the test is skipped,
// or failed if KR0N_REQUIRE_DB_TESTS=1. A configured-but-unsafe URL always fails the test.
func URL(t testing.TB) string {
	t.Helper()
	raw := strings.TrimSpace(os.Getenv(EnvURL))
	if raw == "" {
		msg := EnvURL + " is not set; point it at an isolated test database, e.g. postgres://kr0n:...@localhost:5432/kr0n_test?sslmode=disable (DATABASE_URL is intentionally never used)"
		if os.Getenv(EnvRequire) == "1" {
			t.Fatal(msg)
		}
		t.Skip(msg)
	}
	if err := Validate(raw, os.Getenv("DATABASE_URL"), os.Getenv(EnvAllowNonLocal) == "1"); err != nil {
		t.Fatalf("unsafe %s: %v", EnvURL, err)
	}
	return raw
}

// Migrated returns the validated test URL after bringing its schema to the latest embedded version.
// An unreachable server skips the test (fails it if KR0N_REQUIRE_DB_TESTS=1).
func Migrated(t testing.TB) string {
	t.Helper()
	raw := URL(t)
	requireReachable(t, raw)
	if err := EnsureLatest(raw); err != nil {
		t.Fatalf("prepare test database: %v", err)
	}
	return raw
}

// Pool returns a pgx pool on the migrated test database, closed on test cleanup.
func Pool(t testing.TB) *pgxpool.Pool {
	t.Helper()
	raw := Migrated(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	pool, err := database.NewPostgresPool(ctx, raw)
	if err != nil {
		t.Fatalf("connect to test database: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func requireReachable(t testing.TB, raw string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := pgx.Connect(ctx, raw)
	if err != nil {
		if os.Getenv(EnvRequire) == "1" {
			t.Fatalf("cannot reach test database: %v", err)
		}
		t.Skipf("cannot reach test database: %v", err)
	}
	conn.Close(ctx)
}

// EnsureLatest migrates dbURL to the latest embedded version and verifies the result. It refuses
// dirty databases and databases whose version is newer than this code. Callers must have
// validated dbURL with Validate/URL first.
func EnsureLatest(dbURL string) error {
	latest, err := database.LatestMigrationVersion()
	if err != nil {
		return err
	}
	m, closeFn, err := database.NewMigrator(dbURL)
	if err != nil {
		return err
	}
	defer closeFn()

	version, dirty, err := m.Version()
	switch {
	case errors.Is(err, migrate.ErrNilVersion):
		// fresh database
	case err != nil:
		return fmt.Errorf("read migration version: %w", err)
	case dirty:
		return fmt.Errorf("test database is at dirty migration version %d; drop and recreate it (e.g. DROP DATABASE kr0n_test; CREATE DATABASE kr0n_test)", version)
	case version > latest:
		return fmt.Errorf("test database is at version %d, newer than the latest embedded migration %d; recreate it", version, latest)
	}

	if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return fmt.Errorf("apply migrations: %w", err)
	}
	got, dirty, err := m.Version()
	if err != nil {
		return fmt.Errorf("verify migration version: %w", err)
	}
	if dirty || got != latest {
		return fmt.Errorf("after migration the version is %d (dirty=%t), want %d", got, dirty, latest)
	}
	return nil
}

// NewOwnedDatabase creates a brand-new, empty, uniquely named database on the same server as the
// validated test database and drops it on cleanup. Destructive tests (e.g. migration down) must
// use this instead of the shared test database. It returns the URL of the new database.
func NewOwnedDatabase(t testing.TB) string {
	t.Helper()
	base := URL(t)
	u, err := parse(base)
	if err != nil {
		t.Fatalf("parse test database URL: %v", err)
	}

	name := "kr0n_test_own_" + strings.ReplaceAll(uuid.NewString(), "-", "")[:16]
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	requireReachable(t, base)
	admin, err := pgx.Connect(ctx, base)
	if err != nil {
		t.Fatalf("connect to test database server: %v", err)
	}
	defer admin.Close(ctx)
	if _, err := admin.Exec(ctx, `CREATE DATABASE `+pgx.Identifier{name}.Sanitize()); err != nil {
		t.Fatalf("create owned test database %q: %v", name, err)
	}
	t.Cleanup(func() {
		cctx, ccancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer ccancel()
		c, err := pgx.Connect(cctx, base)
		if err != nil {
			t.Errorf("cleanup: connect to drop %q: %v", name, err)
			return
		}
		defer c.Close(cctx)
		if _, err := c.Exec(cctx, `DROP DATABASE IF EXISTS `+pgx.Identifier{name}.Sanitize()+` WITH (FORCE)`); err != nil {
			t.Errorf("cleanup: drop owned database %q: %v", name, err)
		}
	})

	u.Path = "/" + name
	owned := u.String()
	// Defence in depth: the generated name must itself pass validation.
	if err := Validate(owned, os.Getenv("DATABASE_URL"), os.Getenv(EnvAllowNonLocal) == "1"); err != nil {
		t.Fatalf("owned database failed validation: %v", err)
	}
	return owned
}

func parse(raw string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return nil, fmt.Errorf("parse database URL: %w", err)
	}
	if u.Scheme != "postgres" && u.Scheme != "postgresql" {
		return nil, fmt.Errorf("database URL scheme must be postgres or postgresql, got %q", u.Scheme)
	}
	return u, nil
}

func dbName(u *url.URL) string { return strings.TrimPrefix(u.Path, "/") }

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func sameDatabase(a, b *url.URL) bool {
	port := func(u *url.URL) string {
		if p := u.Port(); p != "" {
			return p
		}
		return "5432"
	}
	return strings.EqualFold(a.Hostname(), b.Hostname()) && port(a) == port(b) && dbName(a) == dbName(b)
}
