package verification

import "context"

// EmailSender defines the contract for dispatching verification emails.
// Owned by the verification domain adhering to Dependency Inversion.
type EmailSender interface {
	SendVerificationEmail(ctx context.Context, recipient, rawToken string) error
}
