package testdb

import (
	"context"
	"errors"
	"runtime"
	"testing"
	"time"

	"github.com/golang-migrate/migrate/v4"
	"github.com/jackc/pgx/v5"

	"github.com/skxm03/kr0n-backend/control-plane/internal/database"
)

func TestValidate(t *testing.T) {
	const dev = "postgres://kr0n:pw@localhost:5432/kr0n?sslmode=disable"
	cases := []struct {
		name     string
		url      string
		dev      string
		nonLocal bool
		wantErr  bool
	}{
		{"test database", "postgres://kr0n:pw@localhost:5432/kr0n_test?sslmode=disable", dev, false, false},
		{"owned throwaway database", "postgres://kr0n:pw@127.0.0.1:5432/kr0n_test_own_ab12cd34", dev, false, false},
		{"ipv6 loopback", "postgresql://kr0n:pw@[::1]:5432/kr0n_test", dev, false, false},
		{"dev database name", "postgres://kr0n:pw@localhost:5432/kr0n", dev, false, true},
		{"postgres maintenance database", "postgres://kr0n:pw@localhost:5432/postgres", dev, false, true},
		{"name merely containing test as substring", "postgres://kr0n:pw@localhost:5432/contest", dev, false, true},
		{"same db as DATABASE_URL even though named test", "postgres://kr0n:pw@localhost:5432/kr0n_test", "postgres://x:y@localhost/kr0n_test", false, true},
		{"non-loopback host", "postgres://kr0n:pw@db.prod.example.com:5432/kr0n_test", dev, false, true},
		{"non-loopback allowed explicitly", "postgres://kr0n:pw@ci-postgres:5432/kr0n_test", dev, true, false},
		{"missing database name", "postgres://kr0n:pw@localhost:5432/", dev, false, true},
		{"wrong scheme", "mysql://kr0n:pw@localhost:3306/kr0n_test", dev, false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := Validate(tc.url, tc.dev, tc.nonLocal)
			if (err != nil) != tc.wantErr {
				t.Fatalf("Validate(%q) err=%v, wantErr=%t", tc.url, err, tc.wantErr)
			}
		})
	}
}

// fakeTB records Skip/Fatal so the helpers' failure behaviour can itself be tested.
type fakeTB struct {
	testing.TB
	skipped, failed bool
	msg             string
}

func (f *fakeTB) Helper()                           {}
func (f *fakeTB) Skip(args ...any)                  { f.skipped = true; runtime.Goexit() }
func (f *fakeTB) Fatal(args ...any)                 { f.failed = true; runtime.Goexit() }
func (f *fakeTB) Fatalf(format string, args ...any) { f.failed = true; runtime.Goexit() }

func runHelper(fn func(tb testing.TB) string) (*fakeTB, string) {
	ft := &fakeTB{}
	var got string
	done := make(chan struct{})
	go func() {
		defer close(done)
		got = fn(ft)
	}()
	<-done
	return ft, got
}

func TestURL_MissingTestDatabaseURLNeverFallsBackToDatabaseURL(t *testing.T) {
	t.Setenv(EnvURL, "")
	t.Setenv(EnvRequire, "")
	// A perfectly valid-looking DATABASE_URL must still be ignored.
	t.Setenv("DATABASE_URL", "postgres://kr0n:pw@localhost:5432/kr0n_test?sslmode=disable")

	ft, got := runHelper(func(tb testing.TB) string { return URL(tb) })
	if !ft.skipped || ft.failed || got != "" {
		t.Fatalf("expected a safe skip without returning any URL, skipped=%t failed=%t url=%q", ft.skipped, ft.failed, got)
	}

	t.Setenv(EnvRequire, "1")
	ft, got = runHelper(func(tb testing.TB) string { return URL(tb) })
	if !ft.failed || got != "" {
		t.Fatalf("with %s=1 a missing %s must fail, failed=%t url=%q", EnvRequire, EnvURL, ft.failed, got)
	}
}

func TestURL_RejectsNonTestDatabaseBeforeAnyConnection(t *testing.T) {
	t.Setenv(EnvRequire, "")
	t.Setenv("DATABASE_URL", "")
	for _, bad := range []string{
		"postgres://kr0n:pw@localhost:5432/kr0n?sslmode=disable",
		"postgres://kr0n:pw@localhost:5432/postgres",
		"postgres://kr0n:pw@prod.example.com:5432/kr0n_test",
	} {
		t.Setenv(EnvURL, bad)
		ft, got := runHelper(func(tb testing.TB) string { return URL(tb) })
		if !ft.failed || got != "" {
			t.Fatalf("URL must fail hard for %q, failed=%t skipped=%t", bad, ft.failed, ft.skipped)
		}
		// Migrated/NewOwnedDatabase go through URL first, so no connection is attempted either.
		ft, _ = runHelper(func(tb testing.TB) string { return Migrated(tb) })
		if !ft.failed {
			t.Fatalf("Migrated must fail hard for %q", bad)
		}
		ft, _ = runHelper(func(tb testing.TB) string { return NewOwnedDatabase(tb) })
		if !ft.failed {
			t.Fatalf("NewOwnedDatabase must fail hard for %q", bad)
		}
	}
}

func TestEnsureLatest_FreshPartialAndDirtyDatabases(t *testing.T) {
	latest, err := database.LatestMigrationVersion()
	if err != nil {
		t.Fatal(err)
	}

	version := func(url string) (uint, bool, error) {
		m, closeFn, err := database.NewMigrator(url)
		if err != nil {
			return 0, false, err
		}
		defer closeFn()
		return m.Version()
	}

	t.Run("fresh database reaches latest schema", func(t *testing.T) {
		url := NewOwnedDatabase(t)
		if _, _, err := version(url); !errors.Is(err, migrate.ErrNilVersion) {
			t.Fatalf("new database should have no version, got %v", err)
		}
		if err := EnsureLatest(url); err != nil {
			t.Fatalf("EnsureLatest on fresh db: %v", err)
		}
		if v, dirty, err := version(url); err != nil || dirty || v != latest {
			t.Fatalf("got version=%d dirty=%t err=%v, want %d", v, dirty, err, latest)
		}
		if err := EnsureLatest(url); err != nil {
			t.Fatalf("EnsureLatest must be idempotent: %v", err)
		}
	})

	t.Run("partially migrated database is brought forward", func(t *testing.T) {
		url := NewOwnedDatabase(t)
		m, closeFn, err := database.NewMigrator(url)
		if err != nil {
			t.Fatal(err)
		}
		if err := m.Migrate(1); err != nil {
			closeFn()
			t.Fatalf("migrate to v1: %v", err)
		}
		closeFn()

		if err := EnsureLatest(url); err != nil {
			t.Fatalf("EnsureLatest on partially migrated db: %v", err)
		}
		if v, dirty, err := version(url); err != nil || dirty || v != latest {
			t.Fatalf("got version=%d dirty=%t err=%v, want %d", v, dirty, err, latest)
		}
	})

	t.Run("dirty database is refused with instructions, not repaired", func(t *testing.T) {
		url := NewOwnedDatabase(t)
		m, closeFn, err := database.NewMigrator(url)
		if err != nil {
			t.Fatal(err)
		}
		if err := m.Force(1); err != nil { // clean v1
			closeFn()
			t.Fatal(err)
		}
		closeFn()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		conn, err := pgx.Connect(ctx, url)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close(ctx)
		if _, err := conn.Exec(ctx, `UPDATE schema_migrations SET dirty = true`); err != nil {
			t.Fatal(err)
		}
		err = EnsureLatest(url)
		if err == nil {
			t.Fatal("dirty database must be refused")
		}
		if v, dirty, _ := version(url); v != 1 || !dirty {
			t.Fatalf("a refused dirty database must be left untouched, got version=%d dirty=%t", v, dirty)
		}
	})
}
