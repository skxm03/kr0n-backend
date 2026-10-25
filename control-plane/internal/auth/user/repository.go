package user

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/skxm03/kr0n-backend/control-plane/internal/auth/verification"
)

// Repository defines persistence operations required by the user domain.
// Owned by package user (the consumer) adhering to Dependency Inversion.
type Repository interface {
	CreateWithPasswordAndVerificationToken(ctx context.Context, u *User, passwordHash string, token *verification.Token) error
	GetByEmailWithPassword(ctx context.Context, email string) (*User, string, error)
	GetByID(ctx context.Context, id uuid.UUID) (*User, error)
	GetByIDWithPassword(ctx context.Context, id uuid.UUID) (*User, string, error)
	RecordLoginFailure(ctx context.Context, userID uuid.UUID, maxAttempts int, lockoutDuration time.Duration, now time.Time) error
	ResetLoginFailures(ctx context.Context, userID uuid.UUID) error
	CreateVerificationToken(ctx context.Context, token *verification.Token) error
	CreatePasswordResetToken(ctx context.Context, token *verification.Token) error
	ConsumePasswordResetAndUpdatePassword(ctx context.Context, tokenHash, newPasswordHash string, now time.Time) (uuid.UUID, error)
	UpdatePassword(ctx context.Context, userID uuid.UUID, newPasswordHash string, revokeSessionExcept *uuid.UUID, now time.Time) error
	ResolveOAuthUser(ctx context.Context, profile OAuthProfile, now time.Time) (*User, error)
}
