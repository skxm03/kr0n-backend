package verification

import "context"

// EmailSender defines the contract for dispatching auth-related transactional emails.
// Owned by the verification domain adhering to Dependency Inversion.
type EmailSender interface {
	SendVerificationEmail(ctx context.Context, recipient, rawToken string) error
	SendPasswordResetEmail(ctx context.Context, recipient, rawToken string) error
}
