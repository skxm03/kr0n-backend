package user

import (
	"context"

	"github.com/skxm03/kr0n-backend/control-plane/internal/auth/verification"
)

// Repository defines persistence operations required by the user domain.
// Owned by package user (the consumer) adhering to Dependency Inversion.
type Repository interface {
	CreateWithPassword(ctx context.Context, u *User, passwordHash string) error
	CreateWithPasswordAndVerificationToken(ctx context.Context, u *User, passwordHash string, token *verification.Token) error
	GetByEmailWithPassword(ctx context.Context, email string) (*User, string, error)
}
