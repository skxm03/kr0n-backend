package repository

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	// ErrInvalidToken indicates the verification token is invalid, malformed, or missing.
	ErrInvalidToken = errors.New("invalid or expired verification token")

	// ErrTokenExpired indicates the verification token has expired.
	// Wraps ErrInvalidToken to allow callers to match generically.
	ErrTokenExpired = fmt.Errorf("%w: token expired", ErrInvalidToken)

	// ErrTokenAlreadyConsumed indicates the verification token was previously consumed.
	// Wraps ErrInvalidToken to prevent revealing token usage history.
	ErrTokenAlreadyConsumed = fmt.Errorf("%w: token already consumed", ErrInvalidToken)
)

// Token represents an email verification or password reset token entity.
type Token struct {
	ID         uuid.UUID
	UserID     uuid.UUID
	TokenHash  string
	ExpiresAt  time.Time
	ConsumedAt *time.Time
	CreatedAt  time.Time
}

// GenerateToken generates a cryptographically secure 32-byte (256-bit entropy)
// random string encoded in hexadecimal. The raw token exists only in memory
// and must never be persisted or logged.
func GenerateToken() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("generate random verification token bytes: %w", err)
	}
	return hex.EncodeToString(bytes), nil
}

// HashToken computes the SHA-256 hexadecimal digest of a raw verification token.
// Only this cryptographic hash is persisted to PostgreSQL.
func HashToken(rawToken string) string {
	h := sha256.Sum256([]byte(rawToken))
	return hex.EncodeToString(h[:])
}

// VerifyTokenHash compares a candidate raw token against a stored hash in constant time
// to prevent timing side-channel attacks.
func VerifyTokenHash(rawToken, storedHash string) bool {
	candidateHash := HashToken(rawToken)
	return subtle.ConstantTimeCompare([]byte(candidateHash), []byte(storedHash)) == 1
}

// VerificationRepository defines persistence operations for email verification tokens.
type VerificationRepository interface {
	// VerifyAndConsume validates the token, locks the record, marks user.email_verified_at = now(),
	// and sets token.consumed_at = now() atomically within a single database transaction.
	VerifyAndConsume(ctx context.Context, tokenHash string, now time.Time) (*Token, error)
}

// PostgresVerificationRepository implements VerificationRepository using PostgreSQL.
type PostgresVerificationRepository struct {
	pool *pgxpool.Pool
}

// NewPostgresVerificationRepository creates a new PostgresVerificationRepository.
func NewPostgresVerificationRepository(pool *pgxpool.Pool) *PostgresVerificationRepository {
	return &PostgresVerificationRepository{pool: pool}
}

// VerifyAndConsume validates the token, locks the record with row-level locking (FOR UPDATE OF t),
// marks the user verified, and consumes the token atomically within a single Read Committed transaction.
// Row-level locking guarantees that concurrent verification attempts using the same token cannot both succeed.
func (r *PostgresVerificationRepository) VerifyAndConsume(ctx context.Context, tokenHash string, now time.Time) (*Token, error) {
	tx, err := r.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return nil, fmt.Errorf("begin verification transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	const selectSQL = `
		SELECT t.id, t.user_id, t.token_hash, t.expires_at, t.consumed_at, t.created_at,
		       u.id, u.status
		FROM email_verification_tokens t
		LEFT JOIN users u ON t.user_id = u.id
		WHERE t.token_hash = $1
		FOR UPDATE OF t;
	`

	var (
		t          Token
		userID     *uuid.UUID
		userStatus *string
	)

	err = tx.QueryRow(ctx, selectSQL, tokenHash).Scan(
		&t.ID,
		&t.UserID,
		&t.TokenHash,
		&t.ExpiresAt,
		&t.ConsumedAt,
		&t.CreatedAt,
		&userID,
		&userStatus,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrInvalidToken
		}
		return nil, fmt.Errorf("query token for verification: %w", err)
	}

	if userID == nil {
		return nil, ErrUserNotFound
	}

	if t.ConsumedAt != nil {
		return nil, ErrTokenAlreadyConsumed
	}

	if !t.ExpiresAt.After(now) {
		return nil, ErrTokenExpired
	}

	if userStatus == nil || *userStatus != string(StatusActive) {
		return nil, ErrUserNotActive
	}

	const updateUserSQL = `
		UPDATE users
		SET email_verified_at = COALESCE(email_verified_at, $1), updated_at = $1
		WHERE id = $2;
	`
	_, err = tx.Exec(ctx, updateUserSQL, now, t.UserID)
	if err != nil {
		return nil, fmt.Errorf("update user email_verified_at: %w", err)
	}

	const updateTokenSQL = `
		UPDATE email_verification_tokens
		SET consumed_at = $1
		WHERE (id = $2 OR user_id = $3) AND consumed_at IS NULL;
	`
	_, err = tx.Exec(ctx, updateTokenSQL, now, t.ID, t.UserID)
	if err != nil {
		return nil, fmt.Errorf("consume verification token: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit verification transaction: %w", err)
	}

	t.ConsumedAt = &now
	return &t, nil
}
