// Package testdb centralises how tests obtain isolated PostgreSQL and Redis instances via
// Testcontainers. Every integration and E2E test must go through it so that no test can ever
// reach a development or production database.
//
// Rules enforced here:
//   - DATABASE_URL is never used as a fallback under any circumstance.
//   - By default, when TEST_DATABASE_URL is unset, testdb automatically provisions an ephemeral
//     PostgreSQL 18 container ("postgres:18-alpine") via Testcontainers with database "kr0n_test".
//   - When TEST_DATABASE_URL is explicitly set, the database name must contain a "test" segment
//     (e.g. kr0n_test), must not match DATABASE_URL, and must be loopback unless
//     KR0N_TEST_ALLOW_NONLOCAL_DB=1 is set explicitly.
//   - Embedded migrations are applied and verified against LatestMigrationVersion(). Dirty or
//     newer-than-code databases are refused rather than silently repaired.
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
	"sync"
	"testing"
	"time"

	"github.com/golang-migrate/migrate/v4"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	tcredis "github.com/testcontainers/testcontainers-go/modules/redis"

	"github.com/skxm03/kr0n-backend/control-plane/internal/database"
)

const (
	// EnvURL is the optional override variable that selects an external integration-test database.
	// When unset, an ephemeral PostgreSQL Testcontainer is started automatically.
	EnvURL = "TEST_DATABASE_URL"
	// EnvRedisAddr is the optional override variable that selects an external test Redis address.
	// When unset, an ephemeral Redis Testcontainer is started automatically.
	EnvRedisAddr = "TEST_REDIS_ADDR"
	// EnvRequire makes missing/unreachable Docker or database configuration a test failure instead of a skip (use in CI).
	EnvRequire = "KR0N_REQUIRE_DB_TESTS"
	// EnvAllowNonLocal permits a non-loopback test database host when TEST_DATABASE_URL is set.
	EnvAllowNonLocal = "KR0N_TEST_ALLOW_NONLOCAL_DB"
	// EnvDisableTestcontainers disables automatic Testcontainer provisioning when TEST_DATABASE_URL is unset.
	EnvDisableTestcontainers = "KR0N_DISABLE_TESTCONTAINERS"

	defaultPostgresImage = "postgres:18-alpine"
	defaultRedisImage    = "redis:7-alpine"
)

var (
	testNameSegment = regexp.MustCompile(`(^|_)test($|_)`)

	pgOnce         sync.Once
	pgContainerURL string
	pgContainerErr error

	redisOnce          sync.Once
	redisContainerAddr string
	redisContainerErr  error
)

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

// startSharedPostgresContainer provisions a single reusable PostgreSQL 18 Testcontainer for the
// current test binary process (automatically reaped by Testcontainers Ryuk on process exit).
func startSharedPostgresContainer() (string, error) {
	pgOnce.Do(func() {
		pgContainerURL, pgContainerErr = runPostgresContainer(context.Background())
	})
	return pgContainerURL, pgContainerErr
}

func runPostgresContainer(ctx context.Context) (connURL string, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("testcontainers postgres panic: %v", r)
		}
	}()

	startupCtx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()

	ctr, err := tcpostgres.Run(
		startupCtx,
		defaultPostgresImage,
		tcpostgres.WithDatabase("kr0n_test"),
		tcpostgres.WithUsername("kr0n_test"),
		tcpostgres.WithPassword("kr0n_test_password"),
		tcpostgres.BasicWaitStrategies(),
	)
	if err != nil {
		return "", fmt.Errorf("start postgres testcontainer: %w", err)
	}
	connStr, err := ctr.ConnectionString(startupCtx, "sslmode=disable")
	if err != nil {
		_ = testcontainers.TerminateContainer(ctr)
		return "", fmt.Errorf("resolve postgres testcontainer connection string: %w", err)
	}
	return connStr, nil
}

// NewContainer starts a dedicated ephemeral PostgreSQL 18 Testcontainer for a single test and
// registers container termination in t.Cleanup.
func NewContainer(t testing.TB) string {
	t.Helper()
	if os.Getenv(EnvDisableTestcontainers) == "1" {
		skipOrFail(t, fmt.Sprintf("%s=1 disables Testcontainers", EnvDisableTestcontainers))
		return ""
	}

	var (
		connStr string
		err     error
	)
	func() {
		defer func() {
			if r := recover(); r != nil {
				err = fmt.Errorf("testcontainers postgres panic: %v", r)
			}
		}()
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cancel()

		ctr, runErr := tcpostgres.Run(
			ctx,
			defaultPostgresImage,
			tcpostgres.WithDatabase("kr0n_test"),
			tcpostgres.WithUsername("kr0n_test"),
			tcpostgres.WithPassword("kr0n_test_password"),
			tcpostgres.BasicWaitStrategies(),
		)
		if runErr != nil {
			err = runErr
			return
		}
		t.Cleanup(func() {
			_ = testcontainers.TerminateContainer(ctr)
		})
		connStr, err = ctr.ConnectionString(ctx, "sslmode=disable")
	}()
	if err != nil {
		skipOrFail(t, fmt.Sprintf("cannot start PostgreSQL Testcontainer: %v", err))
		return ""
	}
	if err := Validate(connStr, os.Getenv("DATABASE_URL"), true); err != nil {
		t.Fatalf("unsafe Testcontainer URL: %v", err)
	}
	return connStr
}

// URL returns a validated PostgreSQL test database URL.
//   - If TEST_DATABASE_URL is explicitly set, it is validated against Validate() before returning.
//   - Otherwise, an ephemeral PostgreSQL 18 Testcontainer is started automatically (unless
//     KR0N_DISABLE_TESTCONTAINERS=1). DATABASE_URL is never used as a fallback.
func URL(t testing.TB) string {
	t.Helper()
	raw := strings.TrimSpace(os.Getenv(EnvURL))
	if raw != "" {
		if err := Validate(raw, os.Getenv("DATABASE_URL"), os.Getenv(EnvAllowNonLocal) == "1"); err != nil {
			t.Fatalf("unsafe %s: %v", EnvURL, err)
		}
		return raw
	}

	if os.Getenv(EnvDisableTestcontainers) == "1" {
		skipOrFail(t, EnvURL+" is not set and "+EnvDisableTestcontainers+"=1 (DATABASE_URL is intentionally never used)")
		return ""
	}

	connStr, err := startSharedPostgresContainer()
	if err != nil {
		skipOrFail(t, fmt.Sprintf("cannot provision PostgreSQL Testcontainer (and %s is not set): %v", EnvURL, err))
		return ""
	}
	if err := Validate(connStr, os.Getenv("DATABASE_URL"), true); err != nil {
		t.Fatalf("unsafe Testcontainer URL: %v", err)
	}
	return connStr
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

// RedisAddr returns the host:port of an isolated Redis 7 Testcontainer (or TEST_REDIS_ADDR if set).
func RedisAddr(t testing.TB) string {
	t.Helper()
	if raw := strings.TrimSpace(os.Getenv(EnvRedisAddr)); raw != "" {
		return raw
	}
	if os.Getenv(EnvDisableTestcontainers) == "1" {
		skipOrFail(t, EnvRedisAddr+" is not set and "+EnvDisableTestcontainers+"=1")
		return ""
	}
	redisOnce.Do(func() {
		redisContainerAddr, redisContainerErr = runRedisContainer(context.Background())
	})
	if redisContainerErr != nil {
		skipOrFail(t, fmt.Sprintf("cannot provision Redis Testcontainer: %v", redisContainerErr))
		return ""
	}
	return redisContainerAddr
}

// RedisClient returns a connected *redis.Client backed by the isolated Redis 7 Testcontainer.
func RedisClient(t testing.TB) *redis.Client {
	t.Helper()
	addr := RedisAddr(t)
	client := redis.NewClient(&redis.Options{Addr: addr})
	t.Cleanup(func() { _ = client.Close() })
	return client
}

func runRedisContainer(ctx context.Context) (endpoint string, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("testcontainers redis panic: %v", r)
		}
	}()

	startupCtx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()

	ctr, err := tcredis.Run(startupCtx, defaultRedisImage)
	if err != nil {
		return "", fmt.Errorf("start redis testcontainer: %w", err)
	}
	ep, err := ctr.Endpoint(startupCtx, "")
	if err != nil {
		_ = testcontainers.TerminateContainer(ctr)
		return "", fmt.Errorf("resolve redis testcontainer endpoint: %w", err)
	}
	return ep, nil
}

func skipOrFail(t testing.TB, msg string) {
	t.Helper()
	if os.Getenv(EnvRequire) == "1" {
		t.Fatal(msg)
	}
	t.Skip(msg)
}

func requireReachable(t testing.TB, raw string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := pgx.Connect(ctx, raw)
	if err != nil {
		skipOrFail(t, fmt.Sprintf("cannot reach test database: %v", err))
		return
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
// validated test database (Testcontainer or TEST_DATABASE_URL) and drops it on cleanup.
// Destructive tests (e.g. migration down) must use this instead of the shared test database.
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
