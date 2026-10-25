package verification

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PostgresRepository implements Repository using PostgreSQL.
type PostgresRepository struct {
	pool *pgxpool.Pool
}

// NewPostgresRepository creates a new PostgresRepository.
func NewPostgresRepository(pool *pgxpool.Pool) *PostgresRepository {
	return &PostgresRepository{pool: pool}
}

// VerifyAndConsume validates the token, locks the record with row-level locking (FOR UPDATE OF t),
// marks the user verified, and consumes the token atomically within a single Read Committed transaction.
// Row-level locking guarantees that concurrent verification attempts using the same token cannot both succeed.
func (r *PostgresRepository) VerifyAndConsume(ctx context.Context, tokenHash string, now time.Time) (*Token, error) {
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

	if userStatus == nil || *userStatus != "active" {
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
