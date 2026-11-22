package service

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/skxm03/kr0n-backend/control-plane/internal/auth/domain"
	"github.com/skxm03/kr0n-backend/control-plane/internal/auth/repository"
	"github.com/skxm03/kr0n-backend/control-plane/internal/email"
)

// OutboxNotifier notifies background workers when a new outbox event is persisted.
type OutboxNotifier interface {
	Notify()
}

// RegisterParams contains input arguments for registering a new user.
type RegisterParams struct {
	Email       string
	Password    string
	DisplayName string
}

// AuthenticateParams contains input arguments for authenticating an existing user.
type AuthenticateParams struct {
	Email    string
	Password string
}

// UserOption defines a functional option for configuring UserService.
type UserOption func(*UserService)

// WithOutboxNotifier wires an outbox notifier to UserService.
func WithOutboxNotifier(notifier OutboxNotifier) UserOption {
	return func(s *UserService) {
		s.notifier = notifier
	}
}

// WithTokenLifetime configures the lifetime of generated verification tokens.
func WithTokenLifetime(lifetime time.Duration) UserOption {
	return func(s *UserService) {
		if lifetime > 0 {
			s.tokenLifetime = lifetime
		}
	}
}

// WithPasswordResetTokenLifetime configures the lifetime of generated password reset tokens.
func WithPasswordResetTokenLifetime(lifetime time.Duration) UserOption {
	return func(s *UserService) {
		if lifetime > 0 {
			s.resetTokenLifetime = lifetime
		}
	}
}

// WithRequireVerifiedEmail configures whether login requires a verified email address.
func WithRequireVerifiedEmail(require bool) UserOption {
	return func(s *UserService) {
		s.requireVerifiedEmail = require
	}
}

// WithSessionRepository wires a session repository to UserService for aggregate coordination.
func WithSessionRepository(sessionRepo repository.SessionRepository) UserOption {
	return func(s *UserService) {
		s.sessionRepo = sessionRepo
	}
}

// WithLockoutPolicy configures the failed login attempt threshold and lockout duration.
func WithLockoutPolicy(maxAttempts int, lockoutDuration time.Duration) UserOption {
	return func(s *UserService) {
		if maxAttempts > 0 {
			s.maxLoginAttempts = maxAttempts
		}
		if lockoutDuration > 0 {
			s.lockoutDuration = lockoutDuration
		}
	}
}

// UserService orchestrates user-related domain capabilities.
type UserService struct {
	repo                 repository.UserRepository
	sessionRepo          repository.SessionRepository
	hasher               PasswordHasher
	notifier             OutboxNotifier
	tokenLifetime        time.Duration
	resetTokenLifetime   time.Duration
	requireVerifiedEmail bool
	maxLoginAttempts     int
	lockoutDuration      time.Duration
}

// NewUserService constructs a UserService.
func NewUserService(repo repository.UserRepository, hasher PasswordHasher, opts ...UserOption) *UserService {
	s := &UserService{
		repo:               repo,
		hasher:             hasher,
		tokenLifetime:      24 * time.Hour,
		resetTokenLifetime: time.Hour,
		maxLoginAttempts:   5,
		lockoutDuration:    15 * time.Minute,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

func newUUIDv7() uuid.UUID {
	if id, err := uuid.NewV7(); err == nil {
		return id
	}
	return uuid.New()
}

// Register validates parameters, applies password policies, computes password hash,
// generates a verification token, and persists user, credentials, verification token, and
// outbox event atomically in a single database transaction.
func (s *UserService) Register(ctx context.Context, params RegisterParams) (*domain.User, error) {
	if err := s.hasher.ValidatePolicy(params.Password); err != nil {
		return nil, err
	}

	newUser, err := domain.NewUser(params.Email, params.DisplayName)
	if err != nil {
		return nil, err
	}

	hash, err := s.hasher.Hash(params.Password)
	if err != nil {
		return nil, fmt.Errorf("hash password: %w", err)
	}

	rawToken, err := domain.GenerateToken()
	if err != nil {
		return nil, fmt.Errorf("generate verification token: %w", err)
	}
	tokenHash := domain.HashToken(rawToken)

	now := time.Now().UTC()
	token := &domain.Token{
		ID:        newUUIDv7(),
		UserID:    newUser.ID,
		TokenHash: tokenHash,
		ExpiresAt: now.Add(s.tokenLifetime),
		CreatedAt: now,
	}

	outboxEv := &domain.OutboxEvent{
		ID:            newUUIDv7(),
		EventType:     domain.EventTypeEmailVerification,
		AggregateType: "user",
		AggregateID:   newUser.ID,
		Payload: map[string]any{
			"id":        newUUIDv7().String(),
			"type":      string(email.TemplateVerifyEmail),
			"recipient": newUser.Email,
			"data": map[string]string{
				"token": rawToken,
			},
			"created_at": now.Format(time.RFC3339),
		},
		Headers:     map[string]any{},
		Status:      domain.OutboxStatusPending,
		CreatedAt:   now,
		ScheduledAt: now,
	}

	if err := s.repo.CreateWithPasswordAndVerificationToken(ctx, newUser, hash, token, outboxEv); err != nil {
		return nil, err
	}

	if s.notifier != nil {
		s.notifier.Notify()
	}

	return newUser, nil
}

// Authenticate verifies user credentials and returns the active user entity.
func (s *UserService) Authenticate(ctx context.Context, params AuthenticateParams) (*domain.User, error) {
	const dummyBcryptHash = "$2a$12$e8I7n.oE/1u9jFq7m5yRyeuG.F/5kX5g5g1wE3l0N4t7M6o3A2Z0i"

	canonicalEmail, err := domain.CanonicalizeEmail(params.Email)
	if err != nil {
		return nil, domain.ErrInvalidCredentials
	}

	u, hash, err := s.repo.GetByEmailWithPassword(ctx, canonicalEmail)
	if err != nil {
		if errors.Is(err, domain.ErrUserNotFound) {
			_ = s.hasher.Compare(dummyBcryptHash, params.Password)
			return nil, domain.ErrInvalidCredentials
		}
		return nil, fmt.Errorf("user lookup: %w", err)
	}

	now := time.Now().UTC()
	if u.LockedUntil != nil && u.LockedUntil.After(now) {
		_ = s.hasher.Compare(dummyBcryptHash, params.Password)
		return nil, domain.ErrInvalidCredentials
	}

	if err := s.hasher.Compare(hash, params.Password); err != nil {
		_ = s.repo.RecordLoginFailure(ctx, u.ID, s.maxLoginAttempts, s.lockoutDuration, now)
		return nil, domain.ErrInvalidCredentials
	}

	if u.FailedLoginAttempts > 0 || u.LockedUntil != nil {
		_ = s.repo.ResetLoginFailures(ctx, u.ID)
	}

	if u.Status != domain.StatusActive {
		return nil, domain.ErrUserNotActive
	}

	if s.requireVerifiedEmail && u.EmailVerifiedAt == nil {
		return nil, domain.ErrEmailNotVerified
	}

	return u, nil
}

// ResendVerification issues a fresh email verification token and sends it if the account exists,
// is active, and is not yet verified.
func (s *UserService) ResendVerification(ctx context.Context, rawEmail string) error {
	canonicalEmail, err := domain.CanonicalizeEmail(rawEmail)
	if err != nil {
		return err
	}

	u, _, err := s.repo.GetByEmailWithPassword(ctx, canonicalEmail)
	if err != nil {
		if errors.Is(err, domain.ErrUserNotFound) {
			return nil
		}
		return fmt.Errorf("lookup user for resend verification: %w", err)
	}

	if u.Status != domain.StatusActive || u.EmailVerifiedAt != nil {
		return nil
	}

	// Cooldown: enforce a strict daily limit of at most 3 resends per 24 hours.
	// If the user registered within the last 24 hours, their initial registration token is also in this window,
	// so the maximum token threshold is 4 (1 registration + 3 resends); otherwise, it is 3.
	now := time.Now().UTC()
	since := now.Add(-24 * time.Hour)
	count, err := s.repo.CountRecentVerificationTokens(ctx, u.ID, since)
	if err != nil {
		return fmt.Errorf("check verification resend limit: %w", err)
	}
	maxAllowed := 3
	if u.CreatedAt.After(since) {
		maxAllowed = 4
	}
	if count >= maxAllowed {
		return domain.ErrResendLimitExceeded
	}

	rawToken, err := domain.GenerateToken()
	if err != nil {
		return fmt.Errorf("generate verification token: %w", err)
	}
	token := &domain.Token{
		ID:        newUUIDv7(),
		UserID:    u.ID,
		TokenHash: domain.HashToken(rawToken),
		ExpiresAt: now.Add(s.tokenLifetime),
		CreatedAt: now,
	}

	outboxEv := &domain.OutboxEvent{
		ID:            newUUIDv7(),
		EventType:     domain.EventTypeEmailVerification,
		AggregateType: "user",
		AggregateID:   u.ID,
		Payload: map[string]any{
			"id":        newUUIDv7().String(),
			"type":      string(email.TemplateVerifyEmail),
			"recipient": u.Email,
			"data": map[string]string{
				"token": rawToken,
			},
			"created_at": now.Format(time.RFC3339),
		},
		Headers:     map[string]any{},
		Status:      domain.OutboxStatusPending,
		CreatedAt:   now,
		ScheduledAt: now,
	}

	if err := s.repo.CreateVerificationToken(ctx, token, outboxEv); err != nil {
		return err
	}

	if s.notifier != nil {
		s.notifier.Notify()
	}
	return nil
}

// RequestPasswordReset issues a fresh password reset token and creates an outbox event atomically.
func (s *UserService) RequestPasswordReset(ctx context.Context, rawEmail string) error {
	canonicalEmail, err := domain.CanonicalizeEmail(rawEmail)
	if err != nil {
		return err
	}

	u, _, err := s.repo.GetByEmailWithPassword(ctx, canonicalEmail)
	if err != nil {
		if errors.Is(err, domain.ErrUserNotFound) {
			return nil
		}
		return fmt.Errorf("lookup user for password reset: %w", err)
	}

	if u.Status != domain.StatusActive {
		return nil
	}

	rawToken, err := domain.GenerateToken()
	if err != nil {
		return fmt.Errorf("generate password reset token: %w", err)
	}
	now := time.Now().UTC()
	token := &domain.Token{
		ID:        newUUIDv7(),
		UserID:    u.ID,
		TokenHash: domain.HashToken(rawToken),
		ExpiresAt: now.Add(s.resetTokenLifetime),
		CreatedAt: now,
	}

	outboxEv := &domain.OutboxEvent{
		ID:            newUUIDv7(),
		EventType:     domain.EventTypePasswordReset,
		AggregateType: "user",
		AggregateID:   u.ID,
		Payload: map[string]any{
			"id":        newUUIDv7().String(),
			"type":      string(email.TemplatePasswordReset),
			"recipient": u.Email,
			"data": map[string]string{
				"token": rawToken,
			},
			"created_at": now.Format(time.RFC3339),
		},
		Headers:     map[string]any{},
		Status:      domain.OutboxStatusPending,
		CreatedAt:   now,
		ScheduledAt: now,
	}

	if err := s.repo.CreatePasswordResetToken(ctx, token, outboxEv); err != nil {
		return err
	}

	if s.notifier != nil {
		s.notifier.Notify()
	}
	return nil
}

// ConfirmPasswordReset validates the new password policy, consumes the reset token, updates
// the user's password hash, resets login lockout state, and coordinates revoking all active sessions.
func (s *UserService) ConfirmPasswordReset(ctx context.Context, rawToken, newPassword string) (uuid.UUID, error) {
	if rawToken == "" {
		return uuid.Nil, domain.ErrInvalidResetToken
	}
	if err := s.hasher.ValidatePolicy(newPassword); err != nil {
		return uuid.Nil, err
	}

	newHash, err := s.hasher.Hash(newPassword)
	if err != nil {
		return uuid.Nil, fmt.Errorf("hash password: %w", err)
	}

	tokenHash := domain.HashToken(rawToken)
	now := time.Now().UTC()
	userID, err := s.repo.ConsumePasswordResetAndUpdatePassword(ctx, tokenHash, newHash, now)
	if err != nil {
		return uuid.Nil, err
	}

	if s.sessionRepo != nil {
		if err := s.sessionRepo.RevokeAllByUserID(ctx, userID, now); err != nil {
			return uuid.Nil, fmt.Errorf("revoke user sessions after reset: %w", err)
		}
	}

	return userID, nil
}

// ChangePassword verifies the user's current password, validates and hashes the new password,
// updates credentials via UserRepository, and coordinates revoking other active sessions via SessionRepository.
func (s *UserService) ChangePassword(ctx context.Context, userID uuid.UUID, currentPassword, newPassword string, currentSessionID *uuid.UUID) error {
	if userID == uuid.Nil {
		return domain.ErrUserNotFound
	}
	if err := s.hasher.ValidatePolicy(newPassword); err != nil {
		return err
	}

	u, currentHash, err := s.repo.GetByIDWithPassword(ctx, userID)
	if err != nil {
		return err
	}
	if u.Status != domain.StatusActive {
		return domain.ErrUserNotActive
	}
	if err := s.hasher.Compare(currentHash, currentPassword); err != nil {
		return domain.ErrInvalidCredentials
	}

	newHash, err := s.hasher.Hash(newPassword)
	if err != nil {
		return fmt.Errorf("hash new password: %w", err)
	}

	now := time.Now().UTC()
	if err := s.repo.UpdatePassword(ctx, userID, newHash, now); err != nil {
		return err
	}

	if s.sessionRepo != nil {
		if currentSessionID != nil && *currentSessionID != uuid.Nil {
			return s.sessionRepo.RevokeAllExcept(ctx, userID, *currentSessionID, now)
		}
		return s.sessionRepo.RevokeAllByUserID(ctx, userID, now)
	}

	return nil
}

// GetProfile retrieves a user's profile by ID.
func (s *UserService) GetProfile(ctx context.Context, userID uuid.UUID) (*domain.User, error) {
	if userID == uuid.Nil {
		return nil, domain.ErrUserNotFound
	}
	return s.repo.GetByID(ctx, userID)
}

// ResolveOAuthUser validates an OAuthProfile (requiring a verified email), canonicalizes the email,
// and resolves/links/creates the user account.
func (s *UserService) ResolveOAuthUser(ctx context.Context, profile domain.OAuthProfile) (*domain.User, error) {
	if !profile.EmailVerified {
		return nil, domain.ErrOAuthEmailNotVerified
	}
	if profile.Provider == "" || profile.ProviderUserID == "" {
		return nil, errors.New("oauth provider and provider_user_id are required")
	}
	canonicalEmail, err := domain.CanonicalizeEmail(profile.Email)
	if err != nil {
		return nil, err
	}
	profile.Email = canonicalEmail
	if profile.DisplayName == "" {
		profile.DisplayName = canonicalEmail
	}
	if len(profile.DisplayName) > 100 {
		profile.DisplayName = profile.DisplayName[:100]
	}

	return s.repo.ResolveOAuthUser(ctx, profile, time.Now().UTC())
}
