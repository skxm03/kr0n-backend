package verification

import (
	"context"
	"errors"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
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

func createTestUser(t *testing.T, pool *pgxpool.Pool, status string) uuid.UUID {
	t.Helper()
	ctx := context.Background()

	userID := uuid.New()
	uniqueEmail := "verif_user_" + userID.String() + "@kr0n.dev"
	const insertSQL = `
		INSERT INTO users (id, email, display_name, status, created_at, updated_at)
		VALUES ($1, $2, $3, $4, now(), now());
	`
	_, err := pool.Exec(ctx, insertSQL, userID, uniqueEmail, "Verification Test User", status)
	if err != nil {
		t.Fatalf("insert test user failed: %v", err)
	}

	return userID
}

func TestPostgresRepository_CreateAndGetByTokenHash(t *testing.T) {
	pool := setupTestPool(t)
	repo := NewPostgresRepository(pool)
	ctx := context.Background()

	testUserID := createTestUser(t, pool, "active")

	rawToken, err := GenerateToken()
	if err != nil {
		t.Fatalf("GenerateToken failed: %v", err)
	}
	tokenHash := HashToken(rawToken)

	now := time.Now().UTC().Truncate(time.Microsecond)
	expiresAt := now.Add(24 * time.Hour)

	tok := &Token{
		ID:        uuid.New(),
		UserID:    testUserID,
		TokenHash: tokenHash,
		ExpiresAt: expiresAt,
		CreatedAt: now,
	}

	// 1. Create verification token
	if err := repo.Create(ctx, tok); err != nil {
		t.Fatalf("Create token failed: %v", err)
	}

	// 2. Lookup by token hash
	retrieved, err := repo.GetByTokenHash(ctx, tokenHash)
	if err != nil {
		t.Fatalf("GetByTokenHash failed: %v", err)
	}

	if retrieved.ID != tok.ID {
		t.Fatalf("expected ID %v, got %v", tok.ID, retrieved.ID)
	}
	if retrieved.UserID != testUserID {
		t.Fatalf("expected UserID %v, got %v", testUserID, retrieved.UserID)
	}
	if retrieved.TokenHash != tokenHash {
		t.Fatalf("expected TokenHash %v, got %v", tokenHash, retrieved.TokenHash)
	}
	if retrieved.ConsumedAt != nil {
		t.Fatal("expected ConsumedAt to be nil")
	}

	// Verify raw token is NEVER found in the database table
	var count int
	err = pool.QueryRow(ctx, "SELECT count(*) FROM email_verification_tokens WHERE token_hash = $1", rawToken).Scan(&count)
	if err != nil {
		t.Fatalf("query failed: %v", err)
	}
	if count != 0 {
		t.Fatalf("CRITICAL SECURITY VIOLATION: raw verification token found in PostgreSQL: count=%d", count)
	}
}

func TestPostgresRepository_VerifyAndConsume_Success(t *testing.T) {
	pool := setupTestPool(t)
	repo := NewPostgresRepository(pool)
	ctx := context.Background()

	testUserID := createTestUser(t, pool, "active")

	rawToken, err := GenerateToken()
	if err != nil {
		t.Fatalf("GenerateToken failed: %v", err)
	}
	tokenHash := HashToken(rawToken)

	now := time.Now().UTC()
	tok := &Token{
		ID:        uuid.New(),
		UserID:    testUserID,
		TokenHash: tokenHash,
		ExpiresAt: now.Add(24 * time.Hour),
		CreatedAt: now,
	}

	if err := repo.Create(ctx, tok); err != nil {
		t.Fatalf("Create token failed: %v", err)
	}

	// Verify initially unverified
	var initialVerifiedAt *time.Time
	err = pool.QueryRow(ctx, "SELECT email_verified_at FROM users WHERE id = $1", testUserID).Scan(&initialVerifiedAt)
	if err != nil {
		t.Fatalf("query email_verified_at failed: %v", err)
	}
	if initialVerifiedAt != nil {
		t.Fatal("expected email_verified_at to be NULL initially")
	}

	// Execute VerifyAndConsume
	verifyTime := time.Now().UTC()
	consumedToken, err := repo.VerifyAndConsume(ctx, tokenHash, verifyTime)
	if err != nil {
		t.Fatalf("VerifyAndConsume failed: %v", err)
	}

	if consumedToken.ConsumedAt == nil {
		t.Fatal("expected ConsumedAt to be set on returned token")
	}

	// Verify user is marked verified in PostgreSQL
	var dbVerifiedAt *time.Time
	err = pool.QueryRow(ctx, "SELECT email_verified_at FROM users WHERE id = $1", testUserID).Scan(&dbVerifiedAt)
	if err != nil {
		t.Fatalf("query email_verified_at failed: %v", err)
	}
	if dbVerifiedAt == nil {
		t.Fatal("expected users.email_verified_at to be populated in PostgreSQL")
	}

	// Verify token is marked consumed in PostgreSQL
	var dbConsumedAt *time.Time
	err = pool.QueryRow(ctx, "SELECT consumed_at FROM email_verification_tokens WHERE id = $1", tok.ID).Scan(&dbConsumedAt)
	if err != nil {
		t.Fatalf("query consumed_at failed: %v", err)
	}
	if dbConsumedAt == nil {
		t.Fatal("expected email_verification_tokens.consumed_at to be populated in PostgreSQL")
	}

	// Second attempt with consumed token must fail
	_, err = repo.VerifyAndConsume(ctx, tokenHash, time.Now().UTC())
	if !errors.Is(err, ErrTokenAlreadyConsumed) {
		t.Fatalf("expected ErrTokenAlreadyConsumed on reuse, got %v", err)
	}
}

func TestPostgresRepository_VerifyAndConsume_ExpiredToken(t *testing.T) {
	pool := setupTestPool(t)
	repo := NewPostgresRepository(pool)
	ctx := context.Background()

	testUserID := createTestUser(t, pool, "active")

	rawToken, _ := GenerateToken()
	tokenHash := HashToken(rawToken)

	now := time.Now().UTC()
	tok := &Token{
		ID:        uuid.New(),
		UserID:    testUserID,
		TokenHash: tokenHash,
		ExpiresAt: now.Add(-1 * time.Hour), // Expired 1 hour ago
		CreatedAt: now.Add(-2 * time.Hour),
	}

	if err := repo.Create(ctx, tok); err != nil {
		t.Fatalf("Create token failed: %v", err)
	}

	_, err := repo.VerifyAndConsume(ctx, tokenHash, now)
	if !errors.Is(err, ErrTokenExpired) {
		t.Fatalf("expected ErrTokenExpired, got %v", err)
	}

	// Confirm user was not verified
	var verifiedAt *time.Time
	_ = pool.QueryRow(ctx, "SELECT email_verified_at FROM users WHERE id = $1", testUserID).Scan(&verifiedAt)
	if verifiedAt != nil {
		t.Fatal("expected user to remain unverified after expired token attempt")
	}
}

func TestPostgresRepository_VerifyAndConsume_Concurrent(t *testing.T) {
	pool := setupTestPool(t)
	repo := NewPostgresRepository(pool)
	ctx := context.Background()

	testUserID := createTestUser(t, pool, "active")

	rawToken, _ := GenerateToken()
	tokenHash := HashToken(rawToken)

	now := time.Now().UTC()
	tok := &Token{
		ID:        uuid.New(),
		UserID:    testUserID,
		TokenHash: tokenHash,
		ExpiresAt: now.Add(24 * time.Hour),
		CreatedAt: now,
	}

	if err := repo.Create(ctx, tok); err != nil {
		t.Fatalf("Create token failed: %v", err)
	}

	const goroutines = 10
	var successCount int64
	var failureCount int64

	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			_, err := repo.VerifyAndConsume(ctx, tokenHash, time.Now().UTC())
			if err == nil {
				atomic.AddInt64(&successCount, 1)
			} else if errors.Is(err, ErrTokenAlreadyConsumed) {
				atomic.AddInt64(&failureCount, 1)
			}
		}()
	}

	wg.Wait()

	if successCount != 1 {
		t.Fatalf("expected exactly 1 successful verification under PostgreSQL row lock, got %d", successCount)
	}
	if failureCount != goroutines-1 {
		t.Fatalf("expected %d failures with ErrTokenAlreadyConsumed, got %d", goroutines-1, failureCount)
	}
}

func TestPostgresRepository_VerifyAndConsume_RollbackOnInactiveUser(t *testing.T) {
	pool := setupTestPool(t)
	repo := NewPostgresRepository(pool)
	ctx := context.Background()

	testUserID := createTestUser(t, pool, "suspended")

	rawToken, _ := GenerateToken()
	tokenHash := HashToken(rawToken)

	now := time.Now().UTC()
	tok := &Token{
		ID:        uuid.New(),
		UserID:    testUserID,
		TokenHash: tokenHash,
		ExpiresAt: now.Add(24 * time.Hour),
		CreatedAt: now,
	}

	if err := repo.Create(ctx, tok); err != nil {
		t.Fatalf("Create token failed: %v", err)
	}

	_, err := repo.VerifyAndConsume(ctx, tokenHash, now)
	if !errors.Is(err, ErrUserNotActive) {
		t.Fatalf("expected ErrUserNotActive, got %v", err)
	}

	// Confirm token was NOT consumed due to transaction rollback
	retrieved, err := repo.GetByTokenHash(ctx, tokenHash)
	if err != nil {
		t.Fatalf("GetByTokenHash failed: %v", err)
	}
	if retrieved.ConsumedAt != nil {
		t.Fatal("expected token to NOT be consumed after transaction rollback")
	}
}
