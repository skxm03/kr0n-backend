package session

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	// ErrSessionNotFound indicates the requested session does not exist.
	ErrSessionNotFound = errors.New("session not found")
	// ErrSessionExpired indicates the session is past its expiration time.
	ErrSessionExpired = errors.New("session expired")
	// ErrSessionRevoked indicates the session has been revoked.
	ErrSessionRevoked = errors.New("session revoked")
	// ErrInvalidRefreshToken indicates the provided refresh token is invalid.
	ErrInvalidRefreshToken = errors.New("invalid refresh token")
)

// Session represents an authenticated user session in the auth domain.
type Session struct {
	ID         uuid.UUID
	UserID     uuid.UUID
	TokenHash  string
	UserAgent  *string
	IPAddress  *net.IP
	ExpiresAt  time.Time
	RevokedAt  *time.Time
	CreatedAt  time.Time
	LastSeenAt time.Time
}

// HashRefreshToken computes the SHA-256 hex digest of a raw refresh token.
// Raw tokens are never persisted to PostgreSQL.
func HashRefreshToken(rawToken string) string {
	h := sha256.Sum256([]byte(rawToken))
	return hex.EncodeToString(h[:])
}

// VerifyRefreshToken performs a constant-time comparison of a candidate raw token against a stored hash.
func VerifyRefreshToken(rawToken, storedHash string) bool {
	candidateHash := HashRefreshToken(rawToken)
	return subtle.ConstantTimeCompare([]byte(candidateHash), []byte(storedHash)) == 1
}

// GenerateRefreshToken creates a cryptographically secure 32-byte opaque random string.
func GenerateRefreshToken() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("generate random bytes: %w", err)
	}
	return hex.EncodeToString(bytes), nil
}

// Repository defines the persistence interface for user sessions.
type Repository interface {
	Create(ctx context.Context, session *Session) error
}

// PostgresRepository implements Repository using PostgreSQL.
type PostgresRepository struct {
	pool *pgxpool.Pool
}

// NewPostgresRepository creates a PostgresRepository backed by pgxpool.
func NewPostgresRepository(pool *pgxpool.Pool) *PostgresRepository {
	return &PostgresRepository{pool: pool}
}

// Create inserts a session atomically into PostgreSQL.
// TokenHash must be the cryptographic hash of the refresh token.
func (r *PostgresRepository) Create(ctx context.Context, s *Session) error {
	const insertSQL = `
		INSERT INTO sessions (id, user_id, token_hash, user_agent, ip_address, expires_at, revoked_at, created_at, last_seen_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9);
	`

	var ipStr *string
	if s.IPAddress != nil {
		str := s.IPAddress.String()
		ipStr = &str
	}

	_, err := r.pool.Exec(ctx, insertSQL,
		s.ID,
		s.UserID,
		s.TokenHash,
		s.UserAgent,
		ipStr,
		s.ExpiresAt,
		s.RevokedAt,
		s.CreatedAt,
		s.LastSeenAt,
	)
	if err != nil {
		return fmt.Errorf("insert session: %w", err)
	}

	return nil
}
