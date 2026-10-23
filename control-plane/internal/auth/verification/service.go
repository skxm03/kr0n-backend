package verification

import (
	"context"
	"strings"
	"time"
)

// Service coordinates verification token validation and user email verification.
type Service struct {
	repo Repository
}

// NewService constructs a verification Service.
func NewService(repo Repository) *Service {
	return &Service{
		repo: repo,
	}
}

// VerifyEmail validates a candidate raw verification token, marks user email verified,
// and consumes the token. It enforces that the token exists, is unexpired, unconsumed,
// and associated with an active user account.
func (s *Service) VerifyEmail(ctx context.Context, rawToken string) error {
	trimmed := strings.TrimSpace(rawToken)
	if trimmed == "" {
		return ErrInvalidToken
	}

	tokenHash := HashToken(trimmed)
	now := time.Now().UTC()

	_, err := s.repo.VerifyAndConsume(ctx, tokenHash, now)
	if err != nil {
		return err
	}

	return nil
}
