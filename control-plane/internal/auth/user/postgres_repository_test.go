package user

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func getTestDatabaseURL() string {
	if url := os.Getenv("TEST_DATABASE_URL"); url != "" {
		return url
	}
	return os.Getenv("DATABASE_URL")
}

func setupTestPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dbURL := getTestDatabaseURL()
	if dbURL == "" {
		t.Skip("skipping postgres integration test: neither TEST_DATABASE_URL nor DATABASE_URL set")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	config, err := pgxpool.ParseConfig(dbURL)
	if err != nil {
		t.Fatalf("parse db config: %v", err)
	}

	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatalf("connect to test db: %v", err)
	}

	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		t.Skipf("cannot reach test db at %s: %v", dbURL, err)
	}

	t.Cleanup(func() {
		pool.Close()
	})

	return pool
}

func TestPostgresRepository_CreateWithPassword_Success(t *testing.T) {
	pool := setupTestPool(t)
	repo := NewPostgresRepository(pool)

	uniqueEmail := "user_" + uuid.New().String() + "@kr0n.dev"
	u, err := NewUser(uniqueEmail, "Test User")
	if err != nil {
		t.Fatalf("NewUser failed: %v", err)
	}

	const passwordHash = "$2a$12$e8I7n.oE/1u9jFq7m5yRyeuG.F/5kX5g5g1"
	ctx := context.Background()

	err = repo.CreateWithPassword(ctx, u, passwordHash)
	if err != nil {
		t.Fatalf("CreateWithPassword failed: %v", err)
	}

	// Verify users table row
	var (
		gotEmail       string
		gotDisplayName string
		gotStatus      string
	)
	err = pool.QueryRow(ctx, "SELECT email, display_name, status FROM users WHERE id = $1", u.ID).
		Scan(&gotEmail, &gotDisplayName, &gotStatus)
	if err != nil {
		t.Fatalf("failed to query users row: %v", err)
	}
	if gotEmail != uniqueEmail || gotDisplayName != "Test User" || gotStatus != "active" {
		t.Fatalf("unexpected user record: email=%q, name=%q, status=%q", gotEmail, gotDisplayName, gotStatus)
	}

	// Verify password_credentials table row
	var gotHash string
	err = pool.QueryRow(ctx, "SELECT password_hash FROM password_credentials WHERE user_id = $1", u.ID).
		Scan(&gotHash)
	if err != nil {
		t.Fatalf("failed to query password_credentials row: %v", err)
	}
	if gotHash != passwordHash {
		t.Fatalf("expected hash %q, got %q", passwordHash, gotHash)
	}
}

func TestPostgresRepository_CreateWithPassword_DuplicateEmail(t *testing.T) {
	pool := setupTestPool(t)
	repo := NewPostgresRepository(pool)

	uniqueEmail := "dup_" + uuid.New().String() + "@kr0n.dev"
	u1, err := NewUser(uniqueEmail, "User One")
	if err != nil {
		t.Fatalf("NewUser 1 failed: %v", err)
	}

	ctx := context.Background()
	const hash = "$2a$12$e8I7n.oE/1u9jFq7m5yRyeuG.F/5kX5g5g1"
	if err := repo.CreateWithPassword(ctx, u1, hash); err != nil {
		t.Fatalf("initial insert failed: %v", err)
	}

	// Try inserting second user with same email
	u2, err := NewUser(uniqueEmail, "User Two")
	if err != nil {
		t.Fatalf("NewUser 2 failed: %v", err)
	}

	err = repo.CreateWithPassword(ctx, u2, hash)
	if err == nil {
		t.Fatal("expected duplicate email error, got nil")
	}
	if !errors.Is(err, ErrEmailAlreadyExists) {
		t.Fatalf("expected ErrEmailAlreadyExists, got %v", err)
	}
}

func TestPostgresRepository_CreateWithPassword_RollbackOnCredentialFailure(t *testing.T) {
	pool := setupTestPool(t)
	repo := NewPostgresRepository(pool)

	uniqueEmail := "rollback_" + uuid.New().String() + "@kr0n.dev"
	u, err := NewUser(uniqueEmail, "Rollback User")
	if err != nil {
		t.Fatalf("NewUser failed: %v", err)
	}

	ctx := context.Background()
	// Empty password hash violates check constraint 'password_hash_non_empty'
	err = repo.CreateWithPassword(ctx, u, "")
	if err == nil {
		t.Fatal("expected failure on empty password hash, got nil")
	}

	// Ensure users row was rolled back and does not exist
	var exists bool
	err = pool.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM users WHERE id = $1)", u.ID).Scan(&exists)
	if err != nil {
		t.Fatalf("failed to query users existence: %v", err)
	}
	if exists {
		t.Fatal("expected users row to be rolled back, but it exists")
	}
}
