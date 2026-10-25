package verification

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/skxm03/kr0n-backend/control-plane/internal/testdb"
)

// setupTestPool returns a pool on the isolated, fully migrated test database (TEST_DATABASE_URL
// only; DATABASE_URL is never used). See internal/testdb.
func setupTestPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	return testdb.Pool(t)
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

func insertTestToken(t *testing.T, pool *pgxpool.Pool, tok *Token) {
	t.Helper()
	const insertSQL = `
		INSERT INTO email_verification_tokens (id, user_id, token_hash, expires_at, consumed_at, created_at)
		VALUES ($1, $2, $3, $4, $5, $6);
	`
	if _, err := pool.Exec(context.Background(), insertSQL,
		tok.ID, tok.UserID, tok.TokenHash, tok.ExpiresAt, tok.ConsumedAt, tok.CreatedAt,
	); err != nil {
		t.Fatalf("insert test token failed: %v", err)
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

	insertTestToken(t, pool, tok)

	// Verify raw token is NEVER found in the database table
	var count int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM email_verification_tokens WHERE token_hash = $1", rawToken).Scan(&count); err != nil {
		t.Fatalf("query failed: %v", err)
	}
	if count != 0 {
		t.Fatalf("CRITICAL SECURITY VIOLATION: raw verification token found in PostgreSQL: count=%d", count)
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

	insertTestToken(t, pool, tok)

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

	insertTestToken(t, pool, tok)

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

	insertTestToken(t, pool, tok)

	_, err := repo.VerifyAndConsume(ctx, tokenHash, now)
	if !errors.Is(err, ErrUserNotActive) {
		t.Fatalf("expected ErrUserNotActive, got %v", err)
	}

	// Confirm token was NOT consumed due to transaction rollback
	var consumedAt *time.Time
	if err := pool.QueryRow(ctx, "SELECT consumed_at FROM email_verification_tokens WHERE token_hash = $1", tokenHash).Scan(&consumedAt); err != nil {
		t.Fatalf("query token consumed_at failed: %v", err)
	}
	if consumedAt != nil {
		t.Fatal("expected token to NOT be consumed after transaction rollback")
	}
}
