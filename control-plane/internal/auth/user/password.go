package user

import (
	"fmt"
	"unicode/utf8"

	"golang.org/x/crypto/bcrypt"
)

// PasswordHasher defines operations for hashing and validating passwords.
type PasswordHasher interface {
	Hash(password string) (string, error)
	ValidatePolicy(password string) error
	Compare(hash, password string) error
}

// BcryptHasher implements PasswordHasher using the bcrypt algorithm.
type BcryptHasher struct {
	cost int
}

// NewBcryptHasher creates a BcryptHasher with the specified cost.
func NewBcryptHasher(cost int) *BcryptHasher {
	if cost < bcrypt.MinCost || cost > bcrypt.MaxCost {
		cost = 12
	}
	return &BcryptHasher{cost: cost}
}

// ValidatePolicy checks that the password satisfies security policies:
// 1. Minimum 8 Unicode characters
// 2. Maximum 72 UTF-8 bytes (bcrypt truncation boundary)
func (b *BcryptHasher) ValidatePolicy(password string) error {
	// Condition 1: Minimum 8 Unicode characters
	if utf8.RuneCountInString(password) < 8 {
		return fmt.Errorf("%w: password must be at least 8 characters", ErrInvalidPassword)
	}

	// Condition 2: Maximum 72 UTF-8 bytes
	if len([]byte(password)) > 72 {
		return fmt.Errorf("%w: password must not exceed 72 bytes", ErrInvalidPassword)
	}

	return nil
}

// Hash computes the bcrypt hash of the provided password.
func (b *BcryptHasher) Hash(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), b.cost)
	if err != nil {
		return "", fmt.Errorf("bcrypt hash failure: %w", err)
	}
	return string(bytes), nil
}

// Compare verifies whether the plain password matches the bcrypt hash.
func (b *BcryptHasher) Compare(hash, password string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
}
