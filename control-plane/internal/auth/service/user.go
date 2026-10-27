package service

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/google/uuid"

	"github.com/skxm03/kr0n-backend/control-plane/internal/auth/repository"
)

// EmailSender defines the contract for dispatching auth-related transactional emails.
type EmailSender interface {
	SendVerificationEmail(ctx context.Context, recipient, rawToken string) error
	SendPasswordResetEmail(ctx context.Context, recipient, rawToken string) error
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

// WithEmailSender configures the email sender used to dispatch verification and password reset emails.
func WithEmailSender(sender EmailSender) UserOption {
	return func(s *UserService) {
		s.emailSender = sender
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
	hasher               PasswordHasher
	emailSender          EmailSender
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

const emailDispatchTimeout = 3 * time.Second

// Register validates parameters, applies password policies, computes password hash,
// generates a verification token, persists user, credentials, and verification token atomically,
// and dispatches a verification email outside the database transaction.
func (s *UserService) Register(ctx context.Context, params RegisterParams) (*repository.User, error) {
	if err := s.hasher.ValidatePolicy(params.Password); err != nil {
		return nil, err
	}

	newUser, err := repository.NewUser(params.Email, params.DisplayName)
	if err != nil {
		return nil, err
	}

	hash, err := s.hasher.Hash(params.Password)
	if err != nil {
		return nil, fmt.Errorf("hash password: %w", err)
	}

	rawToken, err := repository.GenerateToken()
	if err != nil {
		return nil, fmt.Errorf("generate verification token: %w", err)
	}
	tokenHash := repository.HashToken(rawToken)

	now := time.Now().UTC()
	token := &repository.Token{
		ID:        newUUIDv7(),
		UserID:    newUser.ID,
		TokenHash: tokenHash,
		ExpiresAt: now.Add(s.tokenLifetime),
		CreatedAt: now,
	}

	if err := s.repo.CreateWithPasswordAndVerificationToken(ctx, newUser, hash, token); err != nil {
		return nil, err
	}

	if s.emailSender != nil {
		emailCtx, cancel := context.WithTimeout(ctx, emailDispatchTimeout)
		defer cancel()
		if err := s.emailSender.SendVerificationEmail(emailCtx, newUser.Email, rawToken); err != nil {
			log.Printf("failed to dispatch verification email for user %s: %v", newUser.ID, err)
		}
	}

	return newUser, nil
}

// Authenticate verifies user credentials and returns the active user entity.
func (s *UserService) Authenticate(ctx context.Context, params AuthenticateParams) (*repository.User, error) {
	const dummyBcryptHash = "$2a$12$e8I7n.oE/1u9jFq7m5yRyeuG.F/5kX5g5g1wE3l0N4t7M6o3A2Z0i"

	canonicalEmail, err := repository.CanonicalizeEmail(params.Email)
	if err != nil {
		return nil, repository.ErrInvalidCredentials
	}

	u, hash, err := s.repo.GetByEmailWithPassword(ctx, canonicalEmail)
	if err != nil {
		if errors.Is(err, repository.ErrUserNotFound) {
			_ = s.hasher.Compare(dummyBcryptHash, params.Password)
			return nil, repository.ErrInvalidCredentials
		}
		return nil, fmt.Errorf("user lookup: %w", err)
	}

	now := time.Now().UTC()
	if u.LockedUntil != nil && u.LockedUntil.After(now) {
		_ = s.hasher.Compare(dummyBcryptHash, params.Password)
		return nil, repository.ErrInvalidCredentials
	}

	if err := s.hasher.Compare(hash, params.Password); err != nil {
		_ = s.repo.RecordLoginFailure(ctx, u.ID, s.maxLoginAttempts, s.lockoutDuration, now)
		return nil, repository.ErrInvalidCredentials
	}

	if u.FailedLoginAttempts > 0 || u.LockedUntil != nil {
		_ = s.repo.ResetLoginFailures(ctx, u.ID)
	}

	if u.Status != repository.StatusActive {
		return nil, repository.ErrUserNotActive
	}

	if s.requireVerifiedEmail && u.EmailVerifiedAt == nil {
		return nil, repository.ErrEmailNotVerified
	}

	return u, nil
}

// ResendVerification issues a fresh email verification token and sends it if the account exists,
// is active, and is not yet verified.
func (s *UserService) ResendVerification(ctx context.Context, rawEmail string) error {
	canonicalEmail, err := repository.CanonicalizeEmail(rawEmail)
	if err != nil {
		return err
	}

	u, _, err := s.repo.GetByEmailWithPassword(ctx, canonicalEmail)
	if err != nil {
		if errors.Is(err, repository.ErrUserNotFound) {
			return nil
		}
		return fmt.Errorf("lookup user for resend verification: %w", err)
	}

	if u.Status != repository.StatusActive || u.EmailVerifiedAt != nil {
		return nil
	}

	rawToken, err := repository.GenerateToken()
	if err != nil {
		return fmt.Errorf("generate verification token: %w", err)
	}
	now := time.Now().UTC()
	token := &repository.Token{
		ID:        newUUIDv7(),
		UserID:    u.ID,
		TokenHash: repository.HashToken(rawToken),
		ExpiresAt: now.Add(s.tokenLifetime),
		CreatedAt: now,
	}

	if err := s.repo.CreateVerificationToken(ctx, token); err != nil {
		return err
	}

	if s.emailSender != nil {
		emailCtx, cancel := context.WithTimeout(ctx, emailDispatchTimeout)
		defer cancel()
		if err := s.emailSender.SendVerificationEmail(emailCtx, u.Email, rawToken); err != nil {
			log.Printf("failed to dispatch verification email for user %s: %v", u.ID, err)
		}
	}
	return nil
}

// RequestPasswordReset issues a fresh password reset token and sends it if the account exists
// and is active.
func (s *UserService) RequestPasswordReset(ctx context.Context, rawEmail string) error {
	canonicalEmail, err := repository.CanonicalizeEmail(rawEmail)
	if err != nil {
		return err
	}

	u, _, err := s.repo.GetByEmailWithPassword(ctx, canonicalEmail)
	if err != nil {
		if errors.Is(err, repository.ErrUserNotFound) {
			return nil
		}
		return fmt.Errorf("lookup user for password reset: %w", err)
	}

	if u.Status != repository.StatusActive {
		return nil
	}

	rawToken, err := repository.GenerateToken()
	if err != nil {
		return fmt.Errorf("generate password reset token: %w", err)
	}
	now := time.Now().UTC()
	token := &repository.Token{
		ID:        newUUIDv7(),
		UserID:    u.ID,
		TokenHash: repository.HashToken(rawToken),
		ExpiresAt: now.Add(s.resetTokenLifetime),
		CreatedAt: now,
	}

	if err := s.repo.CreatePasswordResetToken(ctx, token); err != nil {
		return err
	}

	if s.emailSender != nil {
		emailCtx, cancel := context.WithTimeout(ctx, emailDispatchTimeout)
		defer cancel()
		if err := s.emailSender.SendPasswordResetEmail(emailCtx, u.Email, rawToken); err != nil {
			log.Printf("failed to dispatch password reset email for user %s: %v", u.ID, err)
		}
	}
	return nil
}

// ConfirmPasswordReset validates the new password policy, consumes the reset token, updates
// the user's password hash, resets login lockout state, and revokes all active sessions.
func (s *UserService) ConfirmPasswordReset(ctx context.Context, rawToken, newPassword string) (uuid.UUID, error) {
	if rawToken == "" {
		return uuid.Nil, repository.ErrInvalidResetToken
	}
	if err := s.hasher.ValidatePolicy(newPassword); err != nil {
		return uuid.Nil, err
	}

	newHash, err := s.hasher.Hash(newPassword)
	if err != nil {
		return uuid.Nil, fmt.Errorf("hash password: %w", err)
	}

	tokenHash := repository.HashToken(rawToken)
	return s.repo.ConsumePasswordResetAndUpdatePassword(ctx, tokenHash, newHash, time.Now().UTC())
}

// ChangePassword verifies the user's current password, validates and hashes the new password,
// updates credentials, and revokes all other active sessions.
func (s *UserService) ChangePassword(ctx context.Context, userID uuid.UUID, currentPassword, newPassword string, currentSessionID *uuid.UUID) error {
	if userID == uuid.Nil {
		return repository.ErrUserNotFound
	}
	if err := s.hasher.ValidatePolicy(newPassword); err != nil {
		return err
	}

	u, currentHash, err := s.repo.GetByIDWithPassword(ctx, userID)
	if err != nil {
		return err
	}
	if u.Status != repository.StatusActive {
		return repository.ErrUserNotActive
	}
	if err := s.hasher.Compare(currentHash, currentPassword); err != nil {
		return repository.ErrInvalidCredentials
	}

	newHash, err := s.hasher.Hash(newPassword)
	if err != nil {
		return fmt.Errorf("hash new password: %w", err)
	}

	return s.repo.UpdatePassword(ctx, userID, newHash, currentSessionID, time.Now().UTC())
}

// GetProfile retrieves a user's profile by ID.
func (s *UserService) GetProfile(ctx context.Context, userID uuid.UUID) (*repository.User, error) {
	if userID == uuid.Nil {
		return nil, repository.ErrUserNotFound
	}
	return s.repo.GetByID(ctx, userID)
}

// ResolveOAuthUser validates an OAuthProfile (requiring a verified email), canonicalizes the email,
// and resolves/links/creates the user account.
func (s *UserService) ResolveOAuthUser(ctx context.Context, profile repository.OAuthProfile) (*repository.User, error) {
	if !profile.EmailVerified {
		return nil, repository.ErrOAuthEmailNotVerified
	}
	if profile.Provider == "" || profile.ProviderUserID == "" {
		return nil, errors.New("oauth provider and provider_user_id are required")
	}
	canonicalEmail, err := repository.CanonicalizeEmail(profile.Email)
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
