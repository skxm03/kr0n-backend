package user

import (
	"errors"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func TestBcryptHasher_Policy(t *testing.T) {
	hasher := NewBcryptHasher(12)

	tests := []struct {
		name      string
		password  string
		expectErr error
	}{
		{
			name:      "too short: 7 ascii characters",
			password:  "1234567",
			expectErr: ErrInvalidPassword,
		},
		{
			name:      "too short: 7 unicode characters",
			password:  "こんにちは12", // 5 Japanese runes + 2 ascii = 7 runes
			expectErr: ErrInvalidPassword,
		},
		{
			name:     "valid: exactly 8 ascii characters",
			password: "12345678",
		},
		{
			name:     "valid: 8 unicode characters (multibyte)",
			password: "こんにちは世界！", // 8 runes (24 bytes)
		},
		{
			name:     "valid: exactly 72 ascii bytes",
			password: strings.Repeat("a", 72),
		},
		{
			name:      "too long: 73 ascii bytes",
			password:  strings.Repeat("a", 73),
			expectErr: ErrInvalidPassword,
		},
		{
			name:      "too long: multibyte runes exceeding 72 bytes",
			password:  strings.Repeat("世", 25), // 25 runes * 3 bytes = 75 bytes
			expectErr: ErrInvalidPassword,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := hasher.ValidatePolicy(tc.password)
			if tc.expectErr != nil {
				if err == nil {
					t.Fatalf("expected error wrapping %v, got nil", tc.expectErr)
				}
				if !errors.Is(err, tc.expectErr) {
					t.Fatalf("expected error %v, got %v", tc.expectErr, err)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestBcryptHasher_HashAndVerify(t *testing.T) {
	// Using min cost in unit tests for execution speed
	hasher := NewBcryptHasher(bcrypt.MinCost)

	password := "SecretPassword123!"
	hash, err := hasher.Hash(password)
	if err != nil {
		t.Fatalf("hasher.Hash failed: %v", err)
	}

	if len(hash) == 0 {
		t.Fatal("expected non-empty hash")
	}

	// Verify against bcrypt directly
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)); err != nil {
		t.Fatalf("hash verification failed: %v", err)
	}

	// Verify incorrect password fails
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte("WrongPassword123!")); err == nil {
		t.Fatal("expected password comparison mismatch, but it succeeded")
	}
}
