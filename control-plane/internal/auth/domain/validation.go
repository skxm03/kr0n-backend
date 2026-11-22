package domain

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"net/mail"
	"strings"
	"time"

	"github.com/google/uuid"
)

// CanonicalizeEmail normalizes and validates an email address according to domain invariants.
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
	id, err := uuid.NewV7()
	if err != nil {
		id = uuid.New()
	}
	return &User{
		ID:          id,
		Email:       email,
		DisplayName: displayName,
		Status:      StatusActive,
		CreatedAt:   now,
		UpdatedAt:   now,
	}, nil
}

// HashRefreshToken computes the SHA-256 hex digest of a raw refresh token.
func HashRefreshToken(rawToken string) string {
	h := sha256.Sum256([]byte(rawToken))
	return hex.EncodeToString(h[:])
}

// VerifyRefreshToken performs a constant-time comparison of a candidate raw token against a stored hash.
func VerifyRefreshToken(rawToken, storedHash string) bool {
	candidateHash := HashRefreshToken(rawToken)
	return subtle.ConstantTimeCompare([]byte(candidateHash), []byte(storedHash)) == 1
}

// GenerateRefreshToken creates a cryptographically secure 32-byte opaque random string.
func GenerateRefreshToken() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("generate random bytes: %w", err)
	}
	return hex.EncodeToString(bytes), nil
}

// GenerateToken generates a cryptographically secure 32-byte hex token.
func GenerateToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate random token: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// HashToken computes a SHA-256 hex digest of a token string.
func HashToken(raw string) string {
	h := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(h[:])
}

// VerifyToken compares a candidate raw token against a stored hash in constant time.
func VerifyToken(candidate, storedHash string) bool {
	candidateHash := HashToken(candidate)
	return subtle.ConstantTimeCompare([]byte(candidateHash), []byte(storedHash)) == 1
}

// APITokenPrefix is the mandatory prefix for personal/org API tokens.
const APITokenPrefix = "kr0n_pat_"

// LastUsedWriteInterval bounds how often api_tokens.last_used_at is written per token.
const LastUsedWriteInterval = 5 * time.Minute

// GenerateAPIToken generates a `kr0n_pat_<64 hex>` secret, its display prefix, and its SHA-256 hash.
func GenerateAPIToken() (rawToken, prefix, tokenHash string, err error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", "", "", fmt.Errorf("generate api token entropy: %w", err)
	}
	rawToken = APITokenPrefix + hex.EncodeToString(b)
	prefix = rawToken[:len(APITokenPrefix)+8]
	tokenHash = HashAPIToken(rawToken)
	return rawToken, prefix, tokenHash, nil
}

// HashAPIToken computes the SHA-256 hex digest of a raw API token.
func HashAPIToken(rawToken string) string {
	h := sha256.Sum256([]byte(rawToken))
	return hex.EncodeToString(h[:])
}

// VerifyAPITokenHash compares a raw API token's SHA-256 digest against storedHash in constant time.
func VerifyAPITokenHash(rawToken, storedHash string) bool {
	h := HashAPIToken(rawToken)
	return subtle.ConstantTimeCompare([]byte(h), []byte(storedHash)) == 1
}
