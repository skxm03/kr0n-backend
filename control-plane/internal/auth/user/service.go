package user

import (
	"context"
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
