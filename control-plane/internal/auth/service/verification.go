package service

import (
	"context"
	"strings"
	"time"

	"github.com/skxm03/kr0n-backend/control-plane/internal/auth/repository"
)

// VerificationService coordinates verification token validation and user email verification.
type VerificationService struct {
	repo repository.VerificationRepository
}

// NewVerificationService constructs a VerificationService.
func NewVerificationService(repo repository.VerificationRepository) *VerificationService {
	return &VerificationService{
		repo: repo,
	}
}

// VerifyEmail validates a candidate raw verification token, marks user email verified,
// and consumes the token. It enforces that the token exists, is unexpired, unconsumed,
// and associated with an active user account.
func (s *VerificationService) VerifyEmail(ctx context.Context, rawToken string) error {
	trimmed := strings.TrimSpace(rawToken)
	if trimmed == "" {
		return repository.ErrInvalidToken
	}

	tokenHash := repository.HashToken(trimmed)
	now := time.Now().UTC()

	_, err := s.repo.VerifyAndConsume(ctx, tokenHash, now)
	if err != nil {
		return err
	}

	return nil
}
