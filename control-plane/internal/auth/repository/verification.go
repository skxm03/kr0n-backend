package repository

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/skxm03/kr0n-backend/control-plane/internal/auth/domain"
)

// GenerateToken generates a cryptographically secure 32-byte hex token.
func GenerateToken() (string, error) {
	return domain.GenerateToken()
}

// HashToken computes the SHA-256 hexadecimal digest of a raw verification token.
func HashToken(rawToken string) string {
	return domain.HashToken(rawToken)
}

// VerifyTokenHash compares a candidate raw token against a stored hash in constant time.
func VerifyTokenHash(rawToken, storedHash string) bool {
	return domain.VerifyToken(rawToken, storedHash)
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
