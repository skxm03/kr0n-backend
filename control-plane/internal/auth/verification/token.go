package verification

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
)

var (
	// ErrInvalidToken indicates the verification token is invalid, malformed, or missing.
	ErrInvalidToken = errors.New("invalid or expired verification token")

	// ErrTokenExpired indicates the verification token has expired.
	// Wraps ErrInvalidToken to allow callers to match generically.
	ErrTokenExpired = fmt.Errorf("%w: token expired", ErrInvalidToken)

	// ErrTokenAlreadyConsumed indicates the verification token was previously consumed.
	// Wraps ErrInvalidToken to prevent revealing token usage history.
	ErrTokenAlreadyConsumed = fmt.Errorf("%w: token already consumed", ErrInvalidToken)

	// ErrUserNotFound indicates the user associated with the token does not exist.
	ErrUserNotFound = errors.New("user not found")

	// ErrUserNotActive indicates the user account is suspended or deactivated.
	ErrUserNotActive = errors.New("user account is not active")
)

// Token represents an email verification token entity.
type Token struct {
	ID         uuid.UUID
	UserID     uuid.UUID
	TokenHash  string
	ExpiresAt  time.Time
	ConsumedAt *time.Time
	CreatedAt  time.Time
}

// GenerateToken generates a cryptographically secure 32-byte (256-bit entropy)
// random string encoded in hexadecimal. The raw token exists only in memory
// and must never be persisted or logged.
func GenerateToken() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("generate random verification token bytes: %w", err)
	}
	return hex.EncodeToString(bytes), nil
}

// HashToken computes the SHA-256 hexadecimal digest of a raw verification token.
// Only this cryptographic hash is persisted to PostgreSQL.
func HashToken(rawToken string) string {
	h := sha256.Sum256([]byte(rawToken))
	return hex.EncodeToString(h[:])
}

// VerifyTokenHash compares a candidate raw token against a stored hash in constant time
// to prevent timing side-channel attacks.
func VerifyTokenHash(rawToken, storedHash string) bool {
	candidateHash := HashToken(rawToken)
	return subtle.ConstantTimeCompare([]byte(candidateHash), []byte(storedHash)) == 1
}
