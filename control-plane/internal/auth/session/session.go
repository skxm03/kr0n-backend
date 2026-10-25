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
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/skxm03/kr0n-backend/control-plane/internal/auth/user"
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

// RotateFn defines the callback executed within a session rotation transaction.
// It receives the current session and user status, allowing the caller to validate invariants
// and generate fresh credentials before atomically committing the rotation.
type RotateFn func(sess *Session, userStatus user.Status) (newTokenHash string, newExpiresAt time.Time, err error)

// Repository defines the persistence interface for user sessions.
type Repository interface {
	Create(ctx context.Context, session *Session) error
	GetByTokenHash(ctx context.Context, tokenHash string) (*Session, error)
	Rotate(ctx context.Context, oldTokenHash string, now time.Time, fn RotateFn) (*Session, error)
	RevokeByTokenHash(ctx context.Context, tokenHash string, revokedAt time.Time) error
	ListActiveByUserID(ctx context.Context, userID uuid.UUID, now time.Time) ([]Session, error)
	RevokeByID(ctx context.Context, userID, sessionID uuid.UUID, revokedAt time.Time) error
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

// GetByTokenHash retrieves a session by its token hash.
func (r *PostgresRepository) GetByTokenHash(ctx context.Context, tokenHash string) (*Session, error) {
	const selectSQL = `
		SELECT id, user_id, token_hash, user_agent, host(ip_address), expires_at, revoked_at, created_at, last_seen_at
		FROM sessions
		WHERE token_hash = $1;
	`

	var (
		s     Session
		ipStr *string
	)

	err := r.pool.QueryRow(ctx, selectSQL, tokenHash).Scan(
		&s.ID,
		&s.UserID,
		&s.TokenHash,
		&s.UserAgent,
		&ipStr,
		&s.ExpiresAt,
		&s.RevokedAt,
		&s.CreatedAt,
		&s.LastSeenAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrSessionNotFound
		}
		return nil, fmt.Errorf("query session by token hash: %w", err)
	}

	if ipStr != nil {
		ip := net.ParseIP(*ipStr)
		s.IPAddress = &ip
	}

	return &s, nil
}

// Rotate executes atomic refresh-token rotation in a single transaction.
// Row-level locking (FOR UPDATE OF s) ensures that concurrent requests for the same token
// cannot both succeed.
//
// Token Reuse Detection:
// Every rotated token hash is recorded in refresh_token_history. If a token hash is not found
// on active sessions but exists in refresh_token_history, the entire session is immediately
// revoked (revoked_at = now) to mitigate refresh token theft.
func (r *PostgresRepository) Rotate(ctx context.Context, oldTokenHash string, now time.Time, fn RotateFn) (*Session, error) {
	tx, err := r.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return nil, fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	const selectSQL = `
		SELECT s.id, s.user_id, s.token_hash, s.user_agent, host(s.ip_address), s.expires_at, s.revoked_at, s.created_at, s.last_seen_at,
		       u.status
		FROM sessions s
		JOIN users u ON s.user_id = u.id
		WHERE s.token_hash = $1
		FOR UPDATE OF s;
	`

	var (
		s         Session
		ipStr     *string
		statusStr string
	)

	err = tx.QueryRow(ctx, selectSQL, oldTokenHash).Scan(
		&s.ID,
		&s.UserID,
		&s.TokenHash,
		&s.UserAgent,
		&ipStr,
		&s.ExpiresAt,
		&s.RevokedAt,
		&s.CreatedAt,
		&s.LastSeenAt,
		&statusStr,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			var compromisedSessionID uuid.UUID
			histErr := tx.QueryRow(ctx, `
				SELECT session_id
				FROM refresh_token_history
				WHERE token_hash = $1
			`, oldTokenHash).Scan(&compromisedSessionID)
			if histErr == nil {
				_, _ = tx.Exec(ctx, `
					UPDATE sessions
					SET revoked_at = COALESCE(revoked_at, $1)
					WHERE id = $2
				`, now, compromisedSessionID)
				_ = tx.Commit(ctx)
				return nil, ErrSessionRevoked
			}
			return nil, ErrSessionNotFound
		}
		return nil, fmt.Errorf("query session for rotation: %w", err)
	}

	if ipStr != nil {
		ip := net.ParseIP(*ipStr)
		s.IPAddress = &ip
	}

	newTokenHash, newExpiresAt, err := fn(&s, user.Status(statusStr))
	if err != nil {
		return nil, err
	}

	const insertHistorySQL = `
		INSERT INTO refresh_token_history (token_hash, session_id, user_id, rotated_at)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (token_hash) DO NOTHING;
	`
	if _, err := tx.Exec(ctx, insertHistorySQL, oldTokenHash, s.ID, s.UserID, now); err != nil {
		return nil, fmt.Errorf("record refresh token history: %w", err)
	}

	const updateSQL = `
		UPDATE sessions
		SET token_hash = $1, last_seen_at = $2, expires_at = $3
		WHERE id = $4;
	`

	_, err = tx.Exec(ctx, updateSQL, newTokenHash, now, newExpiresAt, s.ID)
	if err != nil {
		return nil, fmt.Errorf("update session token hash: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit session rotation: %w", err)
	}

	s.TokenHash = newTokenHash
	s.LastSeenAt = now
	s.ExpiresAt = newExpiresAt

	return &s, nil
}

// RevokeByTokenHash marks the session as revoked by setting revoked_at timestamp.
// It is idempotent and does not reveal whether the session existed.
func (r *PostgresRepository) RevokeByTokenHash(ctx context.Context, tokenHash string, revokedAt time.Time) error {
	const updateSQL = `
		UPDATE sessions
		SET revoked_at = COALESCE(revoked_at, $1)
		WHERE token_hash = $2;
	`

	_, err := r.pool.Exec(ctx, updateSQL, revokedAt, tokenHash)
	if err != nil {
		return fmt.Errorf("revoke session by token hash: %w", err)
	}

	return nil
}

// ListActiveByUserID returns all non-revoked, non-expired sessions for a user ordered by last_seen_at DESC.
func (r *PostgresRepository) ListActiveByUserID(ctx context.Context, userID uuid.UUID, now time.Time) ([]Session, error) {
	const selectSQL = `
		SELECT id, user_id, token_hash, user_agent, host(ip_address), expires_at, revoked_at, created_at, last_seen_at
		FROM sessions
		WHERE user_id = $1 AND revoked_at IS NULL AND expires_at > $2
		ORDER BY last_seen_at DESC;
	`
	rows, err := r.pool.Query(ctx, selectSQL, userID, now)
	if err != nil {
		return nil, fmt.Errorf("query active sessions: %w", err)
	}
	defer rows.Close()

	var out []Session
	for rows.Next() {
		var (
			s     Session
			ipStr *string
		)
		if err := rows.Scan(
			&s.ID,
			&s.UserID,
			&s.TokenHash,
			&s.UserAgent,
			&ipStr,
			&s.ExpiresAt,
			&s.RevokedAt,
			&s.CreatedAt,
			&s.LastSeenAt,
		); err != nil {
			return nil, fmt.Errorf("scan session: %w", err)
		}
		if ipStr != nil {
			ip := net.ParseIP(*ipStr)
			s.IPAddress = &ip
		}
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate active sessions: %w", err)
	}
	return out, nil
}

// RevokeByID revokes a specific session belonging to userID. Returns ErrSessionNotFound if no matching session exists.
func (r *PostgresRepository) RevokeByID(ctx context.Context, userID, sessionID uuid.UUID, revokedAt time.Time) error {
	const updateSQL = `
		UPDATE sessions
		SET revoked_at = COALESCE(revoked_at, $1)
		WHERE id = $2 AND user_id = $3;
	`
	tag, err := r.pool.Exec(ctx, updateSQL, revokedAt, sessionID, userID)
	if err != nil {
		return fmt.Errorf("revoke session by id: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrSessionNotFound
	}
	return nil
}
