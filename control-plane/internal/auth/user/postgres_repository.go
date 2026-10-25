package user

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgerrcode"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/skxm03/kr0n-backend/control-plane/internal/auth/verification"
)

// PostgresRepository implements Repository using PostgreSQL.
type PostgresRepository struct {
	pool *pgxpool.Pool
}

// NewPostgresRepository creates a new PostgresRepository.
func NewPostgresRepository(pool *pgxpool.Pool) *PostgresRepository {
	return &PostgresRepository{pool: pool}
}

// CreateWithPasswordAndVerificationToken persists a User, PasswordCredentials, and optionally an
// EmailVerificationToken in a single atomic database transaction. If any insert fails,
// the entire transaction is rolled back, leaving behind no partially initialized account.
func (r *PostgresRepository) CreateWithPasswordAndVerificationToken(ctx context.Context, u *User, passwordHash string, token *verification.Token) error {
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

	if token != nil {
		const insertTokenSQL = `
			INSERT INTO email_verification_tokens (id, user_id, token_hash, expires_at, created_at)
			VALUES ($1, $2, $3, $4, $5);
		`
		_, err = tx.Exec(ctx, insertTokenSQL,
			token.ID,
			token.UserID,
			token.TokenHash,
			token.ExpiresAt,
			token.CreatedAt,
		)
		if err != nil {
			return fmt.Errorf("insert verification token: %w", err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit transaction: %w", err)
	}

	return nil
}

// GetByEmailWithPassword retrieves a user and their password hash by canonical email.
// Returns ErrUserNotFound if no record exists for the given email.
func (r *PostgresRepository) GetByEmailWithPassword(ctx context.Context, email string) (*User, string, error) {
	const selectSQL = `
		SELECT u.id, u.email, u.display_name, u.avatar_url, u.status, u.email_verified_at,
		       u.failed_login_attempts, u.locked_until, u.created_at, u.updated_at,
		       p.password_hash
		FROM users u
		JOIN password_credentials p ON u.id = p.user_id
		WHERE u.email = $1;
	`

	var (
		u            User
		passwordHash string
		statusStr    string
	)

	err := r.pool.QueryRow(ctx, selectSQL, email).Scan(
		&u.ID,
		&u.Email,
		&u.DisplayName,
		&u.AvatarURL,
		&statusStr,
		&u.EmailVerifiedAt,
		&u.FailedLoginAttempts,
		&u.LockedUntil,
		&u.CreatedAt,
		&u.UpdatedAt,
		&passwordHash,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, "", ErrUserNotFound
		}
		return nil, "", fmt.Errorf("query user by email: %w", err)
	}

	u.Status = Status(statusStr)
	return &u, passwordHash, nil
}

// GetByID retrieves a user by ID.
func (r *PostgresRepository) GetByID(ctx context.Context, id uuid.UUID) (*User, error) {
	const selectSQL = `
		SELECT id, email, display_name, avatar_url, status, email_verified_at,
		       failed_login_attempts, locked_until, created_at, updated_at
		FROM users
		WHERE id = $1;
	`
	var (
		u         User
		statusStr string
	)
	err := r.pool.QueryRow(ctx, selectSQL, id).Scan(
		&u.ID,
		&u.Email,
		&u.DisplayName,
		&u.AvatarURL,
		&statusStr,
		&u.EmailVerifiedAt,
		&u.FailedLoginAttempts,
		&u.LockedUntil,
		&u.CreatedAt,
		&u.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrUserNotFound
		}
		return nil, fmt.Errorf("query user by id: %w", err)
	}
	u.Status = Status(statusStr)
	return &u, nil
}

// GetByIDWithPassword retrieves a user and their password hash by user ID.
func (r *PostgresRepository) GetByIDWithPassword(ctx context.Context, id uuid.UUID) (*User, string, error) {
	const selectSQL = `
		SELECT u.id, u.email, u.display_name, u.avatar_url, u.status, u.email_verified_at,
		       u.failed_login_attempts, u.locked_until, u.created_at, u.updated_at,
		       p.password_hash
		FROM users u
		JOIN password_credentials p ON u.id = p.user_id
		WHERE u.id = $1;
	`
	var (
		u            User
		passwordHash string
		statusStr    string
	)
	err := r.pool.QueryRow(ctx, selectSQL, id).Scan(
		&u.ID,
		&u.Email,
		&u.DisplayName,
		&u.AvatarURL,
		&statusStr,
		&u.EmailVerifiedAt,
		&u.FailedLoginAttempts,
		&u.LockedUntil,
		&u.CreatedAt,
		&u.UpdatedAt,
		&passwordHash,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, "", ErrUserNotFound
		}
		return nil, "", fmt.Errorf("query user by id with password: %w", err)
	}
	u.Status = Status(statusStr)
	return &u, passwordHash, nil
}

// RecordLoginFailure increments failed_login_attempts and locks the account when maxAttempts is reached.
func (r *PostgresRepository) RecordLoginFailure(ctx context.Context, userID uuid.UUID, maxAttempts int, lockoutDuration time.Duration, now time.Time) error {
	const updateSQL = `
		UPDATE users
		SET failed_login_attempts = CASE
		        WHEN locked_until IS NOT NULL AND locked_until <= $2 THEN 1
		        ELSE failed_login_attempts + 1
		    END,
		    locked_until = CASE
		        WHEN (CASE WHEN locked_until IS NOT NULL AND locked_until <= $2 THEN 1 ELSE failed_login_attempts + 1 END) >= $3
		        THEN $4
		        ELSE locked_until
		    END,
		    updated_at = $2
		WHERE id = $1;
	`
	lockUntil := now.Add(lockoutDuration)
	_, err := r.pool.Exec(ctx, updateSQL, userID, now, maxAttempts, lockUntil)
	if err != nil {
		return fmt.Errorf("record login failure: %w", err)
	}
	return nil
}

// ResetLoginFailures resets failed_login_attempts and locked_until after a successful login.
func (r *PostgresRepository) ResetLoginFailures(ctx context.Context, userID uuid.UUID) error {
	const updateSQL = `
		UPDATE users
		SET failed_login_attempts = 0,
		    locked_until = NULL,
		    updated_at = $2
		WHERE id = $1;
	`
	_, err := r.pool.Exec(ctx, updateSQL, userID, time.Now().UTC())
	if err != nil {
		return fmt.Errorf("reset login failures: %w", err)
	}
	return nil
}

// CreateVerificationToken invalidates any prior unconsumed verification tokens for the user and
// inserts the new email verification token in a single transaction.
func (r *PostgresRepository) CreateVerificationToken(ctx context.Context, token *verification.Token) error {
	tx, err := r.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	if _, err := tx.Exec(ctx, `
		UPDATE email_verification_tokens
		SET consumed_at = $2
		WHERE user_id = $1 AND consumed_at IS NULL;
	`, token.UserID, token.CreatedAt); err != nil {
		return fmt.Errorf("invalidate previous verification tokens: %w", err)
	}

	const insertSQL = `
		INSERT INTO email_verification_tokens (id, user_id, token_hash, expires_at, created_at)
		VALUES ($1, $2, $3, $4, $5);
	`
	if _, err := tx.Exec(ctx, insertSQL, token.ID, token.UserID, token.TokenHash, token.ExpiresAt, token.CreatedAt); err != nil {
		return fmt.Errorf("insert verification token: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit verification token: %w", err)
	}
	return nil
}

// CreatePasswordResetToken invalidates any prior unconsumed password reset tokens for the user and
// inserts the new password reset token in a single transaction.
func (r *PostgresRepository) CreatePasswordResetToken(ctx context.Context, token *verification.Token) error {
	tx, err := r.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	if _, err := tx.Exec(ctx, `
		UPDATE password_reset_tokens
		SET consumed_at = $2
		WHERE user_id = $1 AND consumed_at IS NULL;
	`, token.UserID, token.CreatedAt); err != nil {
		return fmt.Errorf("invalidate previous password reset tokens: %w", err)
	}

	const insertSQL = `
		INSERT INTO password_reset_tokens (id, user_id, token_hash, expires_at, created_at)
		VALUES ($1, $2, $3, $4, $5);
	`
	if _, err := tx.Exec(ctx, insertSQL, token.ID, token.UserID, token.TokenHash, token.ExpiresAt, token.CreatedAt); err != nil {
		return fmt.Errorf("insert password reset token: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit password reset token: %w", err)
	}
	return nil
}

// ConsumePasswordResetAndUpdatePassword atomically consumes a password reset token, updates the
// user's password hash, clears login lockout state, and revokes all active sessions.
func (r *PostgresRepository) ConsumePasswordResetAndUpdatePassword(ctx context.Context, tokenHash, newPasswordHash string, now time.Time) (uuid.UUID, error) {
	tx, err := r.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return uuid.Nil, fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	const selectSQL = `
		SELECT t.id, t.user_id, t.expires_at, t.consumed_at, u.status
		FROM password_reset_tokens t
		JOIN users u ON u.id = t.user_id
		WHERE t.token_hash = $1
		FOR UPDATE OF t, u;
	`
	var (
		tokenID    uuid.UUID
		userID     uuid.UUID
		expiresAt  time.Time
		consumedAt *time.Time
		userStatus string
	)
	err = tx.QueryRow(ctx, selectSQL, tokenHash).Scan(&tokenID, &userID, &expiresAt, &consumedAt, &userStatus)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return uuid.Nil, ErrInvalidResetToken
		}
		return uuid.Nil, fmt.Errorf("query password reset token: %w", err)
	}

	if consumedAt != nil || !now.Before(expiresAt) {
		return uuid.Nil, ErrInvalidResetToken
	}

	if Status(userStatus) != StatusActive {
		return uuid.Nil, ErrUserNotActive
	}

	const consumeSQL = `
		UPDATE password_reset_tokens
		SET consumed_at = $1
		WHERE id = $2 AND consumed_at IS NULL;
	`
	tag, err := tx.Exec(ctx, consumeSQL, now, tokenID)
	if err != nil {
		return uuid.Nil, fmt.Errorf("consume password reset token: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return uuid.Nil, ErrInvalidResetToken
	}

	// Invalidate any other remaining unconsumed reset tokens for this user.
	if _, err := tx.Exec(ctx, `
		UPDATE password_reset_tokens
		SET consumed_at = $1
		WHERE user_id = $2 AND consumed_at IS NULL;
	`, now, userID); err != nil {
		return uuid.Nil, fmt.Errorf("invalidate remaining password reset tokens: %w", err)
	}

	const upsertCredSQL = `
		INSERT INTO password_credentials (user_id, password_hash, created_at, updated_at)
		VALUES ($1, $2, $3, $3)
		ON CONFLICT (user_id) DO UPDATE
		SET password_hash = EXCLUDED.password_hash,
		    updated_at = EXCLUDED.updated_at;
	`
	if _, err := tx.Exec(ctx, upsertCredSQL, userID, newPasswordHash, now); err != nil {
		return uuid.Nil, fmt.Errorf("update password credentials: %w", err)
	}

	const resetLockoutSQL = `
		UPDATE users
		SET failed_login_attempts = 0,
		    locked_until = NULL,
		    updated_at = $1
		WHERE id = $2;
	`
	if _, err := tx.Exec(ctx, resetLockoutSQL, now, userID); err != nil {
		return uuid.Nil, fmt.Errorf("reset lockout state: %w", err)
	}

	const revokeSessionsSQL = `
		UPDATE sessions
		SET revoked_at = $1
		WHERE user_id = $2 AND revoked_at IS NULL;
	`
	if _, err := tx.Exec(ctx, revokeSessionsSQL, now, userID); err != nil {
		return uuid.Nil, fmt.Errorf("revoke user sessions: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return uuid.Nil, fmt.Errorf("commit transaction: %w", err)
	}
	return userID, nil
}

// UpdatePassword updates the user's password hash and revokes active sessions (except revokeSessionExcept when provided).
func (r *PostgresRepository) UpdatePassword(ctx context.Context, userID uuid.UUID, newPasswordHash string, revokeSessionExcept *uuid.UUID, now time.Time) error {
	tx, err := r.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	const updateCredSQL = `
		UPDATE password_credentials
		SET password_hash = $1,
		    updated_at = $2
		WHERE user_id = $3;
	`
	tag, err := tx.Exec(ctx, updateCredSQL, newPasswordHash, now, userID)
	if err != nil {
		return fmt.Errorf("update password credentials: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return ErrUserNotFound
	}

	if revokeSessionExcept != nil && *revokeSessionExcept != uuid.Nil {
		const revokeOtherSQL = `
			UPDATE sessions
			SET revoked_at = $1
			WHERE user_id = $2 AND id <> $3 AND revoked_at IS NULL;
		`
		if _, err := tx.Exec(ctx, revokeOtherSQL, now, userID, *revokeSessionExcept); err != nil {
			return fmt.Errorf("revoke other sessions: %w", err)
		}
	} else {
		const revokeAllSQL = `
			UPDATE sessions
			SET revoked_at = $1
			WHERE user_id = $2 AND revoked_at IS NULL;
		`
		if _, err := tx.Exec(ctx, revokeAllSQL, now, userID); err != nil {
			return fmt.Errorf("revoke sessions: %w", err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit transaction: %w", err)
	}
	return nil
}

// ResolveOAuthUser finds an existing user by OAuth identity, links an existing user by matching
// verified email, or creates a new user + oauth_identities row in a single transaction.
//
// Security policy for existing accounts matched by email:
//   - Only provider-verified emails (profile.EmailVerified == true) are ever accepted.
//   - If the existing local user has already verified their email (email_verified_at IS NOT NULL),
//     the OAuth identity is linked while preserving the user's verified password credentials and
//     active sessions.
//   - If the existing local user has NOT verified their email (email_verified_at IS NULL), whoever
//     created the password-based registration never proved ownership of the email address. To
//     prevent pre-account takeover (Trojan account linking), linking the verified OAuth identity
//     atomically purges the unverified password_credentials, revokes any pre-existing sessions,
//     consumes any pending verification/reset tokens, resets lockout counters, and marks the
//     account verified under the OAuth owner's control.
func (r *PostgresRepository) ResolveOAuthUser(ctx context.Context, profile OAuthProfile, now time.Time) (*User, error) {
	if !profile.EmailVerified {
		return nil, ErrOAuthEmailNotVerified
	}
	if profile.Provider == "" || profile.ProviderUserID == "" || profile.Email == "" {
		return nil, ErrOAuthEmailNotVerified
	}

	for attempt := 0; attempt < 2; attempt++ {
		u, retry, err := r.resolveOAuthUserTx(ctx, profile, now)
		if err == nil {
			return u, nil
		}
		if !retry {
			return nil, err
		}
	}
	return nil, ErrOAuthAccountConflict
}

func (r *PostgresRepository) resolveOAuthUserTx(ctx context.Context, profile OAuthProfile, now time.Time) (*User, bool, error) {
	tx, err := r.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return nil, false, fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	// 1. Check if oauth_identities already links (provider, provider_user_id)
	const selectByOAuthSQL = `
		SELECT u.id, u.email, u.display_name, u.avatar_url, u.status, u.email_verified_at,
		       u.failed_login_attempts, u.locked_until, u.created_at, u.updated_at
		FROM oauth_identities oi
		JOIN users u ON u.id = oi.user_id
		WHERE oi.provider = $1 AND oi.provider_user_id = $2
		FOR UPDATE OF u;
	`
	var (
		u         User
		statusStr string
	)
	err = tx.QueryRow(ctx, selectByOAuthSQL, profile.Provider, profile.ProviderUserID).Scan(
		&u.ID, &u.Email, &u.DisplayName, &u.AvatarURL, &statusStr, &u.EmailVerifiedAt,
		&u.FailedLoginAttempts, &u.LockedUntil, &u.CreatedAt, &u.UpdatedAt,
	)
	if err == nil {
		u.Status = Status(statusStr)
		if u.Status != StatusActive {
			return nil, false, ErrUserNotActive
		}
		if u.EmailVerifiedAt == nil {
			if _, err := tx.Exec(ctx, `UPDATE users SET email_verified_at = $1, updated_at = $1 WHERE id = $2`, now, u.ID); err != nil {
				return nil, false, fmt.Errorf("mark oauth user verified: %w", err)
			}
			u.EmailVerifiedAt = &now
			u.UpdatedAt = now
		}
		if err := tx.Commit(ctx); err != nil {
			return nil, false, fmt.Errorf("commit transaction: %w", err)
		}
		return &u, false, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return nil, false, fmt.Errorf("query oauth identity: %w", err)
	}

	// 2. Look up existing user by canonical email (auto-link only because profile.EmailVerified is true)
	const selectByEmailSQL = `
		SELECT id, email, display_name, avatar_url, status, email_verified_at,
		       failed_login_attempts, locked_until, created_at, updated_at
		FROM users
		WHERE email = $1
		FOR UPDATE;
	`
	err = tx.QueryRow(ctx, selectByEmailSQL, profile.Email).Scan(
		&u.ID, &u.Email, &u.DisplayName, &u.AvatarURL, &statusStr, &u.EmailVerifiedAt,
		&u.FailedLoginAttempts, &u.LockedUntil, &u.CreatedAt, &u.UpdatedAt,
	)
	if err == nil {
		u.Status = Status(statusStr)
		if u.Status != StatusActive {
			return nil, false, ErrUserNotActive
		}
		// Check if an OAuth identity for this (user_id, provider) already exists (e.g. from a
		// concurrent callback that committed while we were starting).
		var existingProviderUID string
		err := tx.QueryRow(ctx, `
			SELECT provider_user_id FROM oauth_identities
			WHERE user_id = $1 AND provider = $2;
		`, u.ID, profile.Provider).Scan(&existingProviderUID)
		switch {
		case err == nil:
			if existingProviderUID != profile.ProviderUserID {
				return nil, false, ErrOAuthAccountConflict
			}
		case errors.Is(err, pgx.ErrNoRows):
			const linkSQL = `
				INSERT INTO oauth_identities (id, user_id, provider, provider_user_id, created_at, updated_at)
				VALUES ($1, $2, $3, $4, $5, $5);
			`
			if _, err := tx.Exec(ctx, linkSQL, uuid.New(), u.ID, profile.Provider, profile.ProviderUserID, now); err != nil {
				var pgErr *pgconn.PgError
				if errors.As(err, &pgErr) && pgErr.Code == pgerrcode.UniqueViolation {
					return nil, false, ErrOAuthAccountConflict
				}
				return nil, false, fmt.Errorf("link oauth identity: %w", err)
			}
		default:
			return nil, false, fmt.Errorf("check existing oauth identity: %w", err)
		}

		if u.EmailVerifiedAt == nil {
			// Unverified local account reclamation: purge unverified password credentials,
			// revoke any pre-existing sessions, and invalidate pending tokens in the same tx.
			if _, err := tx.Exec(ctx, `DELETE FROM password_credentials WHERE user_id = $1`, u.ID); err != nil {
				return nil, false, fmt.Errorf("delete unverified password credentials: %w", err)
			}
			if _, err := tx.Exec(ctx, `UPDATE sessions SET revoked_at = $1 WHERE user_id = $2 AND revoked_at IS NULL`, now, u.ID); err != nil {
				return nil, false, fmt.Errorf("revoke unverified user sessions: %w", err)
			}
			if _, err := tx.Exec(ctx, `UPDATE email_verification_tokens SET consumed_at = $1 WHERE user_id = $2 AND consumed_at IS NULL`, now, u.ID); err != nil {
				return nil, false, fmt.Errorf("consume pending verification tokens: %w", err)
			}
			if _, err := tx.Exec(ctx, `UPDATE password_reset_tokens SET consumed_at = $1 WHERE user_id = $2 AND consumed_at IS NULL`, now, u.ID); err != nil {
				return nil, false, fmt.Errorf("consume pending password reset tokens: %w", err)
			}
			displayName := u.DisplayName
			if profile.DisplayName != "" {
				displayName = profile.DisplayName
			}
			if _, err := tx.Exec(ctx, `
				UPDATE users
				SET email_verified_at = $1,
				    display_name = $2,
				    avatar_url = COALESCE($3, avatar_url),
				    failed_login_attempts = 0,
				    locked_until = NULL,
				    updated_at = $1
				WHERE id = $4
			`, now, displayName, profile.AvatarURL, u.ID); err != nil {
				return nil, false, fmt.Errorf("verify linked user email: %w", err)
			}
			u.EmailVerifiedAt = &now
			u.DisplayName = displayName
			if profile.AvatarURL != nil {
				u.AvatarURL = profile.AvatarURL
			}
			u.FailedLoginAttempts = 0
			u.LockedUntil = nil
			u.UpdatedAt = now
		}
		if err := tx.Commit(ctx); err != nil {
			return nil, false, fmt.Errorf("commit transaction: %w", err)
		}
		return &u, false, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return nil, false, fmt.Errorf("query user by email for oauth: %w", err)
	}

	// 3. Create new user and oauth_identities row
	u = User{
		ID:              uuid.New(),
		Email:           profile.Email,
		DisplayName:     profile.DisplayName,
		AvatarURL:       profile.AvatarURL,
		Status:          StatusActive,
		EmailVerifiedAt: &now,
		CreatedAt:       now,
		UpdatedAt:       now,
	}
	const insertUserSQL = `
		INSERT INTO users (id, email, email_verified_at, display_name, avatar_url, status, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $7);
	`
	if _, err := tx.Exec(ctx, insertUserSQL, u.ID, u.Email, u.EmailVerifiedAt, u.DisplayName, u.AvatarURL, string(u.Status), now); err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == pgerrcode.UniqueViolation {
			return nil, true, err
		}
		return nil, false, fmt.Errorf("insert oauth user: %w", err)
	}

	const insertIdentitySQL = `
		INSERT INTO oauth_identities (id, user_id, provider, provider_user_id, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $5);
	`
	if _, err := tx.Exec(ctx, insertIdentitySQL, uuid.New(), u.ID, profile.Provider, profile.ProviderUserID, now); err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && errors.As(err, &pgErr) && pgErr.Code == pgerrcode.UniqueViolation {
			return nil, true, err
		}
		return nil, false, fmt.Errorf("insert oauth identity: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, false, fmt.Errorf("commit transaction: %w", err)
	}
	return &u, false, nil
}
