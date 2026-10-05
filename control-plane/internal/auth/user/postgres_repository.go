package user

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgerrcode"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
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

// CreateWithPassword persists a User and their PasswordCredentials in a single atomic transaction.
func (r *PostgresRepository) CreateWithPassword(ctx context.Context, u *User, passwordHash string) error {
	tx, err := r.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	const insertUserSQL = `
		INSERT INTO users (id, email, display_name, avatar_url, status, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7);
	`
	_, err = tx.Exec(ctx, insertUserSQL,
		u.ID,
		u.Email,
		u.DisplayName,
		u.AvatarURL,
		string(u.Status),
		u.CreatedAt,
		u.UpdatedAt,
	)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == pgerrcode.UniqueViolation {
			if pgErr.ConstraintName == "users_email_key" {
				return ErrEmailAlreadyExists
			}
		}
		return fmt.Errorf("insert user: %w", err)
	}

	const insertCredSQL = `
		INSERT INTO password_credentials (user_id, password_hash, created_at, updated_at)
		VALUES ($1, $2, $3, $4);
	`
	_, err = tx.Exec(ctx, insertCredSQL,
		u.ID,
		passwordHash,
		u.CreatedAt,
		u.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("insert password credentials: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit transaction: %w", err)
	}

	return nil
}
