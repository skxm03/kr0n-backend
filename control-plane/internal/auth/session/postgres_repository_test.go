package session

import (
	"context"
	"net"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/skxm03/kr0n-backend/control-plane/internal/auth/user"
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
	if err := userRepo.CreateWithPassword(ctx, u, "$2a$12$e8I7n.oE/1u9jFq7m5yRyeuG.F/5kX5g5g1"); err != nil {
		t.Fatalf("CreateWithPassword failed: %v", err)
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

