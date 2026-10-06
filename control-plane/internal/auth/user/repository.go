package user

import "context"

// Repository defines persistence operations required by the user domain.
// Owned by package user (the consumer) adhering to Dependency Inversion.
type Repository interface {
	CreateWithPassword(ctx context.Context, u *User, passwordHash string) error
	GetByEmailWithPassword(ctx context.Context, email string) (*User, string, error)
}
