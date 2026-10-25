package verification

import (
	"context"
	"time"
)

// Repository defines persistence operations for email verification tokens.
// Owned by package verification adhering to Dependency Inversion.
type Repository interface {
	// VerifyAndConsume validates the token, locks the record, marks user.email_verified_at = now(),
	// and sets token.consumed_at = now() atomically within a single database transaction.
	VerifyAndConsume(ctx context.Context, tokenHash string, now time.Time) (*Token, error)
}
