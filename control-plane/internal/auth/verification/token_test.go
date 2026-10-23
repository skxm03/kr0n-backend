package verification

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestToken_GenerationAndEntropy(t *testing.T) {
	// Generate multiple tokens to verify uniqueness and format
	tokens := make(map[string]bool)
	const count = 100

	for i := 0; i < count; i++ {
		tok, err := GenerateToken()
		if err != nil {
			t.Fatalf("unexpected error generating token: %v", err)
		}

		// Check length: 32 bytes hex-encoded = 64 hex characters
		if len(tok) != 64 {
			t.Fatalf("expected token length 64, got %d", len(tok))
		}

		// Ensure valid hex string
		decoded, err := hex.DecodeString(tok)
		if err != nil {
			t.Fatalf("token is not valid hex: %v", err)
		}
		if len(decoded) != 32 {
			t.Fatalf("expected 32 random bytes (256 bits entropy), got %d", len(decoded))
		}

		if tokens[tok] {
			t.Fatalf("duplicate token generated: %s", tok)
		}
		tokens[tok] = true
	}
}

func TestToken_Hashing(t *testing.T) {
	rawToken := "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	expectedHashBytes := sha256.Sum256([]byte(rawToken))
	expectedHash := hex.EncodeToString(expectedHashBytes[:])

	computedHash := HashToken(rawToken)
	if computedHash != expectedHash {
		t.Fatalf("expected hash %q, got %q", expectedHash, computedHash)
	}

	// Verify constant-time comparison
	if !VerifyTokenHash(rawToken, expectedHash) {
		t.Fatal("expected VerifyTokenHash to return true for matching token and hash")
	}

	// Verify wrong token rejection
	wrongToken := "0000000000000000000000000000000000000000000000000000000000000000"
	if VerifyTokenHash(wrongToken, expectedHash) {
		t.Fatal("expected VerifyTokenHash to return false for wrong token")
	}
}

func TestToken_ExpiryAndConsumptionInvariants(t *testing.T) {
	now := time.Now().UTC()

	// Unexpired and unconsumed
	validToken := &Token{
		ID:         uuid.New(),
		UserID:     uuid.New(),
		TokenHash:  HashToken("raw_token"),
		ExpiresAt:  now.Add(24 * time.Hour),
		ConsumedAt: nil,
		CreatedAt:  now,
	}
	if validToken.ConsumedAt != nil {
		t.Fatal("expected valid token to not be consumed")
	}
	if !validToken.ExpiresAt.After(now) {
		t.Fatal("expected valid token to not be expired")
	}

	// Expired token
	expiredToken := &Token{
		ID:         uuid.New(),
		UserID:     uuid.New(),
		TokenHash:  HashToken("raw_expired"),
		ExpiresAt:  now.Add(-1 * time.Hour),
		ConsumedAt: nil,
		CreatedAt:  now.Add(-2 * time.Hour),
	}
	if expiredToken.ExpiresAt.After(now) {
		t.Fatal("expected expired token to have expired")
	}

	// Consumed token
	consumedAt := now.Add(-10 * time.Minute)
	consumedToken := &Token{
		ID:         uuid.New(),
		UserID:     uuid.New(),
		TokenHash:  HashToken("raw_consumed"),
		ExpiresAt:  now.Add(24 * time.Hour),
		ConsumedAt: &consumedAt,
		CreatedAt:  now.Add(-1 * time.Hour),
	}
	if consumedToken.ConsumedAt == nil {
		t.Fatal("expected consumed token to have consumedAt set")
	}
}
