package user

import (
	"context"
	"errors"
	"fmt"
)

// RegisterParams contains input arguments for registering a new user.
type RegisterParams struct {
	Email       string
	Password    string
	DisplayName string
}

// Service orchestrates user-related domain capabilities.
type Service struct {
	repo   Repository
	hasher PasswordHasher
}

// NewService constructs a user Service.
func NewService(repo Repository, hasher PasswordHasher) *Service {
	return &Service{
		repo:   repo,
		hasher: hasher,
	}
}

// Register validates parameters, applies password policies, computes password hash,
// and persists the user entity and credentials.
func (s *Service) Register(ctx context.Context, params RegisterParams) (*User, error) {
	// 1. Validate password policy BEFORE doing expensive hashing or DB operations
	if err := s.hasher.ValidatePolicy(params.Password); err != nil {
		return nil, err
	}

	// 2. Validate and construct domain entity (canonicalizes email, checks display name)
	newUser, err := NewUser(params.Email, params.DisplayName)
	if err != nil {
		return nil, err
	}

	// 3. Compute password hash
	hash, err := s.hasher.Hash(params.Password)
	if err != nil {
		return nil, fmt.Errorf("hash password: %w", err)
	}

	// 4. Persist user and credential atomically
	if err := s.repo.CreateWithPassword(ctx, newUser, hash); err != nil {
		return nil, err
	}

	return newUser, nil
}

// AuthenticateParams contains input arguments for authenticating an existing user.
type AuthenticateParams struct {
	Email    string
	Password string
}

// Authenticate verifies user credentials and returns the active user entity.
// In accordance with security practices, timing attacks and account existence enumeration
// are mitigated by dummy bcrypt comparison when user is not found, and returning generic ErrInvalidCredentials.
func (s *Service) Authenticate(ctx context.Context, params AuthenticateParams) (*User, error) {
	canonicalEmail, err := CanonicalizeEmail(params.Email)
	if err != nil {
		return nil, ErrInvalidCredentials
	}

	u, hash, err := s.repo.GetByEmailWithPassword(ctx, canonicalEmail)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			// Mitigate timing difference by comparing with a dummy bcrypt hash
			const dummyBcryptHash = "$2a$12$e8I7n.oE/1u9jFq7m5yRyeuG.F/5kX5g5g1wE3l0N4t7M6o3A2Z0i"
			_ = s.hasher.Compare(dummyBcryptHash, params.Password)
			return nil, ErrInvalidCredentials
		}
		return nil, fmt.Errorf("user lookup: %w", err)
	}

	if err := s.hasher.Compare(hash, params.Password); err != nil {
		return nil, ErrInvalidCredentials
	}

	if u.Status != StatusActive {
		return nil, ErrUserNotActive
	}

	return u, nil
}
