package user

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/skxm03/kr0n-backend/control-plane/internal/auth/verification"
)

func getTestDatabaseURL() string {
	if url := os.Getenv("TEST_DATABASE_URL"); url != "" {
		return url
	}
	if url := os.Getenv("DATABASE_URL"); url != "" {
		return url
	}
	return "postgres://kr0n:kr0n_dev_password@localhost:5432/kr0n_test?sslmode=disable"
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

func TestPostgresRepository_GetByEmailWithPassword_Success(t *testing.T) {
	pool := setupTestPool(t)
	repo := NewPostgresRepository(pool)

	uniqueEmail := "lookup_" + uuid.New().String() + "@kr0n.dev"
	u, err := NewUser(uniqueEmail, "Lookup User")
	if err != nil {
		t.Fatalf("NewUser failed: %v", err)
	}

	const passwordHash = "$2a$12$e8I7n.oE/1u9jFq7m5yRyeuG.F/5kX5g5g1"
	ctx := context.Background()

	err = repo.CreateWithPassword(ctx, u, passwordHash)
	if err != nil {
		t.Fatalf("CreateWithPassword failed: %v", err)
	}

	gotUser, gotHash, err := repo.GetByEmailWithPassword(ctx, uniqueEmail)
	if err != nil {
		t.Fatalf("GetByEmailWithPassword failed: %v", err)
	}

	if gotUser.ID != u.ID {
		t.Fatalf("expected ID %v, got %v", u.ID, gotUser.ID)
	}
	if gotUser.Email != uniqueEmail {
		t.Fatalf("expected email %s, got %s", uniqueEmail, gotUser.Email)
	}
	if gotUser.DisplayName != "Lookup User" {
		t.Fatalf("expected display name Lookup User, got %s", gotUser.DisplayName)
	}
	if gotUser.Status != StatusActive {
		t.Fatalf("expected status active, got %s", gotUser.Status)
	}
	if gotHash != passwordHash {
		t.Fatalf("expected password hash %s, got %s", passwordHash, gotHash)
	}
}

func TestPostgresRepository_GetByEmailWithPassword_NotFound(t *testing.T) {
	pool := setupTestPool(t)
	repo := NewPostgresRepository(pool)

	ctx := context.Background()
	_, _, err := repo.GetByEmailWithPassword(ctx, "nonexistent@kr0n.dev")
	if !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("expected ErrUserNotFound, got %v", err)
	}
}

func TestPostgresRepository_CreateWithPasswordAndVerificationToken_Success(t *testing.T) {
	pool := setupTestPool(t)
	repo := NewPostgresRepository(pool)
	ctx := context.Background()

	uniqueEmail := "atomic_user_" + uuid.New().String() + "@kr0n.dev"
	u, err := NewUser(uniqueEmail, "Atomic User")
	if err != nil {
		t.Fatalf("NewUser failed: %v", err)
	}

	rawToken, err := verification.GenerateToken()
	if err != nil {
		t.Fatalf("GenerateToken failed: %v", err)
	}
	tokenHash := verification.HashToken(rawToken)

	now := time.Now().UTC()
	token := &verification.Token{
		ID:        uuid.New(),
		UserID:    u.ID,
		TokenHash: tokenHash,
		ExpiresAt: now.Add(24 * time.Hour),
		CreatedAt: now,
	}

	passwordHash := "$2a$12$mockpasswordhashforemailverificationatomic"
	err = repo.CreateWithPasswordAndVerificationToken(ctx, u, passwordHash, token)
	if err != nil {
		t.Fatalf("CreateWithPasswordAndVerificationToken failed: %v", err)
	}

	// 1. Verify user created with email_verified_at = NULL
	var (
		dbVerifiedAt *time.Time
		dbStatus     string
	)
	err = pool.QueryRow(ctx, "SELECT email_verified_at, status FROM users WHERE id = $1", u.ID).Scan(&dbVerifiedAt, &dbStatus)
	if err != nil {
		t.Fatalf("query users table failed: %v", err)
	}
	if dbVerifiedAt != nil {
		t.Fatal("expected users.email_verified_at to be NULL upon creation")
	}
	if dbStatus != "active" {
		t.Fatalf("expected status active, got %s", dbStatus)
	}

	// 2. Verify password_credentials created
	var credUserID uuid.UUID
	err = pool.QueryRow(ctx, "SELECT user_id FROM password_credentials WHERE user_id = $1", u.ID).Scan(&credUserID)
	if err != nil {
		t.Fatalf("query password_credentials failed: %v", err)
	}

	// 3. Verify token created with token_hash (NOT raw token)
	var (
		tokID         uuid.UUID
		tokConsumedAt *time.Time
	)
	err = pool.QueryRow(ctx, "SELECT id, consumed_at FROM email_verification_tokens WHERE token_hash = $1", tokenHash).Scan(&tokID, &tokConsumedAt)
	if err != nil {
		t.Fatalf("query email_verification_tokens failed: %v", err)
	}
	if tokID != token.ID {
		t.Fatalf("expected token ID %v, got %v", token.ID, tokID)
	}
	if tokConsumedAt != nil {
		t.Fatal("expected token to NOT be consumed upon creation")
	}

	// 4. Confirm raw verification token does NOT exist in PostgreSQL
	var rawCount int
	_ = pool.QueryRow(ctx, "SELECT count(*) FROM email_verification_tokens WHERE token_hash = $1", rawToken).Scan(&rawCount)
	if rawCount != 0 {
		t.Fatalf("CRITICAL SECURITY VIOLATION: raw verification token was found in PostgreSQL")
	}
}

func TestPostgresRepository_CreateWithPasswordAndVerificationToken_RollbackOnTokenError(t *testing.T) {
	pool := setupTestPool(t)
	repo := NewPostgresRepository(pool)
	ctx := context.Background()

	// First create an existing token to cause a unique constraint violation on token_hash
	existingEmail := "existing_token_user_" + uuid.New().String() + "@kr0n.dev"
	u1, _ := NewUser(existingEmail, "First User")
	tokenHash := verification.HashToken("collision_" + uuid.New().String())
	now := time.Now().UTC()

	token1 := &verification.Token{
		ID:        uuid.New(),
		UserID:    u1.ID,
		TokenHash: tokenHash,
		ExpiresAt: now.Add(24 * time.Hour),
		CreatedAt: now,
	}
	if err := repo.CreateWithPasswordAndVerificationToken(ctx, u1, "passhash1", token1); err != nil {
		t.Fatalf("setup first user failed: %v", err)
	}

	// Now try to create a second user with the same token_hash
	uniqueEmail2 := "failed_atomic_user_" + uuid.New().String() + "@kr0n.dev"
	u2, _ := NewUser(uniqueEmail2, "Second User")
	token2 := &verification.Token{
		ID:        uuid.New(),
		UserID:    u2.ID,
		TokenHash: tokenHash, // duplicate!
		ExpiresAt: now.Add(24 * time.Hour),
		CreatedAt: now,
	}

	err := repo.CreateWithPasswordAndVerificationToken(ctx, u2, "passhash2", token2)
	if err == nil {
		t.Fatal("expected token unique violation error, got nil")
	}

	// Verify atomicity: u2 must NOT exist in users table
	var count int
	_ = pool.QueryRow(ctx, "SELECT count(*) FROM users WHERE id = $1", u2.ID).Scan(&count)
	if count != 0 {
		t.Fatalf("expected user row to be rolled back, found count=%d", count)
	}

	// Verify password credential for u2 does NOT exist
	_ = pool.QueryRow(ctx, "SELECT count(*) FROM password_credentials WHERE user_id = $1", u2.ID).Scan(&count)
	if count != 0 {
		t.Fatalf("expected password_credentials row to be rolled back, found count=%d", count)
	}
}
