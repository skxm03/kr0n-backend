package session

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/skxm03/kr0n-backend/control-plane/internal/auth/user"
	"github.com/skxm03/kr0n-backend/control-plane/internal/testdb"
)

// setupTestPool returns a pool on the isolated, fully migrated test database (TEST_DATABASE_URL
// only; DATABASE_URL is never used). See internal/testdb.
func setupTestPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	return testdb.Pool(t)
}

func TestPostgresRepository_CreateSession(t *testing.T) {
	pool := setupTestPool(t)
	userRepo := user.NewPostgresRepository(pool)
	sessionRepo := NewPostgresRepository(pool)

	ctx := context.Background()

	// 1. Create a user first so foreign key constraints succeed
	uniqueEmail := "sess_user_" + uuid.New().String() + "@kr0n.dev"
	u, err := user.NewUser(uniqueEmail, "Session User")
	if err != nil {
		t.Fatalf("NewUser failed: %v", err)
	}
	if err := userRepo.CreateWithPasswordAndVerificationToken(ctx, u, "$2a$12$e8I7n.oE/1u9jFq7m5yRyeuG.F/5kX5g5g1", nil); err != nil {
		t.Fatalf("CreateWithPasswordAndVerificationToken failed: %v", err)
	}

	// 2. Generate refresh token and hash
	rawRefreshToken, err := GenerateRefreshToken()
	if err != nil {
		t.Fatalf("GenerateRefreshToken failed: %v", err)
	}
	tokenHash := HashRefreshToken(rawRefreshToken)

	sessionID := uuid.New()
	ua := "Go-http-client/1.1"
	ip := net.ParseIP("127.0.0.1")
	now := time.Now().UTC()
	expiresAt := now.Add(30 * 24 * time.Hour)

	sess := &Session{
		ID:         sessionID,
		UserID:     u.ID,
		TokenHash:  tokenHash,
		UserAgent:  &ua,
		IPAddress:  &ip,
		ExpiresAt:  expiresAt,
		RevokedAt:  nil,
		CreatedAt:  now,
		LastSeenAt: now,
	}

	// 3. Persist session
	if err := sessionRepo.Create(ctx, sess); err != nil {
		t.Fatalf("Create session failed: %v", err)
	}

	// 4. Query database row directly to verify invariants
	var (
		dbUserID     uuid.UUID
		dbTokenHash  string
		dbUserAgent  *string
		dbIPAddress  *string
		dbRevokedAt  *time.Time
		dbExpiresAt  time.Time
		dbCreatedAt  time.Time
		dbLastSeenAt time.Time
	)

	err = pool.QueryRow(ctx, `
		SELECT user_id, token_hash, user_agent, host(ip_address), revoked_at, expires_at, created_at, last_seen_at
		FROM sessions WHERE id = $1
	`, sessionID).Scan(
		&dbUserID,
		&dbTokenHash,
		&dbUserAgent,
		&dbIPAddress,
		&dbRevokedAt,
		&dbExpiresAt,
		&dbCreatedAt,
		&dbLastSeenAt,
	)
	if err != nil {
		t.Fatalf("query sessions row failed: %v", err)
	}

	if dbUserID != u.ID {
		t.Fatalf("expected user_id %s, got %s", u.ID, dbUserID)
	}
	if dbTokenHash != tokenHash {
		t.Fatalf("expected token_hash %s, got %s", tokenHash, dbTokenHash)
	}
	if dbTokenHash == rawRefreshToken {
		t.Fatal("database row MUST NOT contain raw refresh token")
	}
	if !VerifyRefreshToken(rawRefreshToken, dbTokenHash) {
		t.Fatal("stored hash failed verification against raw refresh token")
	}
	if dbUserAgent == nil || *dbUserAgent != ua {
		t.Fatalf("expected user_agent %s, got %v", ua, dbUserAgent)
	}
	if dbIPAddress == nil || *dbIPAddress != "127.0.0.1" {
		t.Fatalf("expected ip_address 127.0.0.1, got %v", dbIPAddress)
	}
	if dbRevokedAt != nil {
		t.Fatalf("expected revoked_at to be nil, got %v", dbRevokedAt)
	}
}

func createTestUserAndSession(t *testing.T, pool *pgxpool.Pool) (*user.User, string, *Session) {
	t.Helper()
	userRepo := user.NewPostgresRepository(pool)
	sessionRepo := NewPostgresRepository(pool)
	ctx := context.Background()

	uniqueEmail := "sess_int_" + uuid.New().String() + "@kr0n.dev"
	u, err := user.NewUser(uniqueEmail, "Integration User")
	if err != nil {
		t.Fatalf("NewUser failed: %v", err)
	}
	if err := userRepo.CreateWithPasswordAndVerificationToken(ctx, u, "$2a$12$e8I7n.oE/1u9jFq7m5yRyeuG.F/5kX5g5g1", nil); err != nil {
		t.Fatalf("CreateWithPasswordAndVerificationToken failed: %v", err)
	}

	rawRefreshToken, err := GenerateRefreshToken()
	if err != nil {
		t.Fatalf("GenerateRefreshToken failed: %v", err)
	}
	tokenHash := HashRefreshToken(rawRefreshToken)

	sessionID := uuid.New()
	ua := "Go-integration-test/1.0"
	ip := net.ParseIP("10.0.0.1")
	now := time.Now().UTC().Truncate(time.Microsecond)
	expiresAt := now.Add(30 * 24 * time.Hour)

	sess := &Session{
		ID:         sessionID,
		UserID:     u.ID,
		TokenHash:  tokenHash,
		UserAgent:  &ua,
		IPAddress:  &ip,
		ExpiresAt:  expiresAt,
		RevokedAt:  nil,
		CreatedAt:  now,
		LastSeenAt: now,
	}

	if err := sessionRepo.Create(ctx, sess); err != nil {
		t.Fatalf("Create session failed: %v", err)
	}

	return u, rawRefreshToken, sess
}

func TestPostgresRepository_GetByTokenHash(t *testing.T) {
	pool := setupTestPool(t)
	sessionRepo := NewPostgresRepository(pool)
	ctx := context.Background()

	u, rawToken, sess := createTestUserAndSession(t, pool)

	// 1. Successful lookup
	fetched, err := sessionRepo.GetByTokenHash(ctx, sess.TokenHash)
	if err != nil {
		t.Fatalf("GetByTokenHash failed: %v", err)
	}
	if fetched.ID != sess.ID {
		t.Fatalf("expected session ID %s, got %s", sess.ID, fetched.ID)
	}
	if fetched.UserID != u.ID {
		t.Fatalf("expected user ID %s, got %s", u.ID, fetched.UserID)
	}
	if fetched.TokenHash != sess.TokenHash {
		t.Fatalf("expected token hash %s, got %s", sess.TokenHash, fetched.TokenHash)
	}
	if !VerifyRefreshToken(rawToken, fetched.TokenHash) {
		t.Fatal("fetched token hash does not match raw token")
	}

	// 2. Nonexistent token hash
	_, err = sessionRepo.GetByTokenHash(ctx, HashRefreshToken("nonexistent_raw_token"))
	if !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("expected ErrSessionNotFound, got %v", err)
	}
}

func TestPostgresRepository_Rotate_Success(t *testing.T) {
	pool := setupTestPool(t)
	sessionRepo := NewPostgresRepository(pool)
	ctx := context.Background()

	u, oldRawToken, sess := createTestUserAndSession(t, pool)
	oldTokenHash := sess.TokenHash

	newRawToken, _ := GenerateRefreshToken()
	newTokenHash := HashRefreshToken(newRawToken)
	now := time.Now().UTC().Truncate(time.Microsecond)
	newExpiresAt := now.Add(30 * 24 * time.Hour)

	var callbackExecuted bool
	rotatedSess, err := sessionRepo.Rotate(ctx, oldTokenHash, now, func(s *Session, userStatus user.Status) (string, time.Time, error) {
		callbackExecuted = true
		if s.ID != sess.ID {
			t.Fatalf("expected session ID %s, got %s", sess.ID, s.ID)
		}
		if userStatus != user.StatusActive {
			t.Fatalf("expected active user status, got %s", userStatus)
		}
		return newTokenHash, newExpiresAt, nil
	})
	if err != nil {
		t.Fatalf("Rotate failed: %v", err)
	}
	if !callbackExecuted {
		t.Fatal("expected rotation callback to be executed")
	}
	if rotatedSess.TokenHash != newTokenHash {
		t.Fatalf("expected session token hash %s, got %s", newTokenHash, rotatedSess.TokenHash)
	}

	// Verify in database: old token hash is GONE
	_, err = sessionRepo.GetByTokenHash(ctx, oldTokenHash)
	if !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("expected old token hash to return ErrSessionNotFound, got %v", err)
	}

	// Verify in database: new token hash EXISTS and points to same session ID
	inDB, err := sessionRepo.GetByTokenHash(ctx, newTokenHash)
	if err != nil {
		t.Fatalf("GetByTokenHash for new token failed: %v", err)
	}
	if inDB.ID != sess.ID {
		t.Fatalf("expected same session ID %s, got %s", sess.ID, inDB.ID)
	}
	if inDB.UserID != u.ID {
		t.Fatalf("expected same user ID %s, got %s", u.ID, inDB.UserID)
	}
	if !VerifyRefreshToken(newRawToken, inDB.TokenHash) {
		t.Fatal("new raw token does not verify against database hash")
	}
	if VerifyRefreshToken(oldRawToken, inDB.TokenHash) {
		t.Fatal("old raw token should NOT verify against database hash")
	}
}

func TestPostgresRepository_RevokedSessionCannotRefresh(t *testing.T) {
	pool := setupTestPool(t)
	sessionRepo := NewPostgresRepository(pool)
	ctx := context.Background()

	_, _, sess := createTestUserAndSession(t, pool)

	// Revoke the session
	revokedAt := time.Now().UTC()
	err := sessionRepo.RevokeByTokenHash(ctx, sess.TokenHash, revokedAt)
	if err != nil {
		t.Fatalf("RevokeByTokenHash failed: %v", err)
	}

	// Attempt rotation
	now := time.Now().UTC()
	_, err = sessionRepo.Rotate(ctx, sess.TokenHash, now, func(s *Session, userStatus user.Status) (string, time.Time, error) {
		if s.RevokedAt != nil {
			return "", time.Time{}, ErrSessionRevoked
		}
		return HashRefreshToken("another_token"), now.Add(24 * time.Hour), nil
	})
	if !errors.Is(err, ErrSessionRevoked) {
		t.Fatalf("expected ErrSessionRevoked, got %v", err)
	}
}

func TestPostgresRepository_ExpiredSessionCannotRefresh(t *testing.T) {
	pool := setupTestPool(t)
	sessionRepo := NewPostgresRepository(pool)
	ctx := context.Background()

	_, _, sess := createTestUserAndSession(t, pool)

	// Manually expire session in DB
	_, err := pool.Exec(ctx, "UPDATE sessions SET expires_at = now() - interval '1 hour' WHERE id = $1", sess.ID)
	if err != nil {
		t.Fatalf("update expires_at failed: %v", err)
	}

	now := time.Now().UTC()
	_, err = sessionRepo.Rotate(ctx, sess.TokenHash, now, func(s *Session, userStatus user.Status) (string, time.Time, error) {
		if !s.ExpiresAt.After(now) {
			return "", time.Time{}, ErrSessionExpired
		}
		return HashRefreshToken("another_token"), now.Add(24 * time.Hour), nil
	})
	if !errors.Is(err, ErrSessionExpired) {
		t.Fatalf("expected ErrSessionExpired, got %v", err)
	}
}

func TestPostgresRepository_ConcurrentRotation(t *testing.T) {
	pool := setupTestPool(t)
	sessionRepo := NewPostgresRepository(pool)
	ctx := context.Background()

	_, _, sess := createTestUserAndSession(t, pool)
	oldTokenHash := sess.TokenHash

	const concurrency = 10
	var (
		wg           sync.WaitGroup
		successCount int
		failureCount int
		mu           sync.Mutex
	)

	wg.Add(concurrency)
	for i := 0; i < concurrency; i++ {
		go func() {
			defer wg.Done()
			newToken, _ := GenerateRefreshToken()
			newHash := HashRefreshToken(newToken)
			now := time.Now().UTC()
			newExpiresAt := now.Add(30 * 24 * time.Hour)

			_, err := sessionRepo.Rotate(ctx, oldTokenHash, now, func(s *Session, userStatus user.Status) (string, time.Time, error) {
				return newHash, newExpiresAt, nil
			})

			mu.Lock()
			defer mu.Unlock()
			if err == nil {
				successCount++
			} else {
				failureCount++
			}
		}()
	}
	wg.Wait()

	if successCount != 1 {
		t.Fatalf("expected exactly 1 concurrent rotation to succeed, got %d", successCount)
	}
	if failureCount != concurrency-1 {
		t.Fatalf("expected %d failures, got %d", concurrency-1, failureCount)
	}
}

func TestPostgresRepository_LogoutRevocationPersistence(t *testing.T) {
	pool := setupTestPool(t)
	sessionRepo := NewPostgresRepository(pool)
	ctx := context.Background()

	_, _, sess := createTestUserAndSession(t, pool)

	// 1. Revoke session
	revokedAt := time.Now().UTC().Truncate(time.Microsecond)
	err := sessionRepo.RevokeByTokenHash(ctx, sess.TokenHash, revokedAt)
	if err != nil {
		t.Fatalf("RevokeByTokenHash failed: %v", err)
	}

	// 2. Query session directly to verify revoked_at is persisted
	stored, err := sessionRepo.GetByTokenHash(ctx, sess.TokenHash)
	if err != nil {
		t.Fatalf("GetByTokenHash failed: %v", err)
	}
	if stored.RevokedAt == nil {
		t.Fatal("expected stored.RevokedAt to be non-nil")
	}

	// 3. Idempotent: revoking again succeeds without error
	err = sessionRepo.RevokeByTokenHash(ctx, sess.TokenHash, time.Now().UTC())
	if err != nil {
		t.Fatalf("second RevokeByTokenHash must succeed: %v", err)
	}

	// 4. Revoking unknown token succeeds without error (leaks no existence information)
	err = sessionRepo.RevokeByTokenHash(ctx, HashRefreshToken("unknown_token_123"), time.Now().UTC())
	if err != nil {
		t.Fatalf("RevokeByTokenHash for unknown token must succeed: %v", err)
	}
}
