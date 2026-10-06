package user

import (
	"errors"
	"fmt"
	"net/mail"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Status represents the operational state of a user account.
type Status string

const (
	StatusActive      Status = "active"
	StatusSuspended   Status = "suspended"
	StatusDeactivated Status = "deactivated"
)

var (
	// ErrEmailAlreadyExists indicates an account is already registered with the given email.
	ErrEmailAlreadyExists = errors.New("email already registered")

	// ErrInvalidEmail indicates the email address violates syntax or length rules.
	ErrInvalidEmail = errors.New("invalid email address")

	// ErrInvalidPassword indicates the password violates policy rules.
	ErrInvalidPassword = errors.New("invalid password")

	// ErrInvalidDisplayName indicates the display name is empty or exceeds limits.
	ErrInvalidDisplayName = errors.New("display name must not be empty")

	// ErrUserNotFound indicates no user entity was found for the given criteria.
	ErrUserNotFound = errors.New("user not found")

	// ErrInvalidCredentials indicates incorrect email or password.
	ErrInvalidCredentials = errors.New("invalid email or password")

	// ErrUserNotActive indicates the user account is suspended or deactivated.
	ErrUserNotActive = errors.New("user account is not active")
)

// User represents the authoritative user entity.
type User struct {
	ID              uuid.UUID
	Email           string
	DisplayName     string
	AvatarURL       *string
	Status          Status
	EmailVerifiedAt *time.Time
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

// CanonicalizeEmail normalizes and validates an email address according to system invariants.
func CanonicalizeEmail(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", fmt.Errorf("%w: email cannot be empty", ErrInvalidEmail)
	}

	if strings.ContainsAny(trimmed, "\r\n\t") {
		return "", fmt.Errorf("%w: email contains invalid control characters", ErrInvalidEmail)
	}

	parsed, err := mail.ParseAddress(trimmed)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrInvalidEmail, err)
	}

	if parsed.Address != trimmed {
		return "", fmt.Errorf("%w: formatted email addresses are not permitted", ErrInvalidEmail)
	}

	canonical := strings.ToLower(trimmed)

	if len(canonical) < 3 || len(canonical) > 254 {
		return "", fmt.Errorf("%w: email length out of bounds (3-254 bytes)", ErrInvalidEmail)
	}

	return canonical, nil
}

// NewUser validates domain invariants and creates a new User entity.
func NewUser(rawEmail, rawDisplayName string) (*User, error) {
	email, err := CanonicalizeEmail(rawEmail)
	if err != nil {
		return nil, err
	}

	displayName := strings.TrimSpace(rawDisplayName)
	if len(displayName) < 1 {
		return nil, ErrInvalidDisplayName
	}
	if len(displayName) > 100 {
		return nil, fmt.Errorf("%w: display name exceeds 100 characters", ErrInvalidDisplayName)
	}

	now := time.Now().UTC()
	return &User{
		ID:          uuid.New(),
		Email:       email,
		DisplayName: displayName,
		Status:      StatusActive,
		CreatedAt:   now,
		UpdatedAt:   now,
	}, nil
}
