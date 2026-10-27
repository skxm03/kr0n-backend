package tests

import (
	"errors"
	"strings"
	"testing"

	"github.com/skxm03/kr0n-backend/control-plane/internal/auth/repository"
)

func TestCanonicalizeEmail(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		want      string
		expectErr error
	}{
		{
			name:  "standard lowercase email",
			input: "user@example.com",
			want:  "user@example.com",
		},
		{
			name:  "uppercase and mixed case converted to lowercase",
			input: "User.Name+Tag@EXAMPLE.COM",
			want:  "user.name+tag@example.com",
		},
		{
			name:  "whitespace trimmed",
			input: "   alice@kr0n.dev \n\t ",
			want:  "alice@kr0n.dev",
		},
		{
			name:      "empty email",
			input:     "",
			expectErr: repository.ErrInvalidEmail,
		},
		{
			name:      "whitespace only email",
			input:     "    ",
			expectErr: repository.ErrInvalidEmail,
		},
		{
			name:      "missing at-sign",
			input:     "userexample.com",
			expectErr: repository.ErrInvalidEmail,
		},
		{
			name:      "missing domain",
			input:     "user@",
			expectErr: repository.ErrInvalidEmail,
		},
		{
			name:      "embedded newline or carriage return",
			input:     "user\r\n@example.com",
			expectErr: repository.ErrInvalidEmail,
		},
		{
			name:      "formatted display name not permitted",
			input:     "Alice Wonderland <alice@example.com>",
			expectErr: repository.ErrInvalidEmail,
		},
		{
			name:      "exceeds RFC max length 254 bytes",
			input:     strings.Repeat("a", 250) + "@domain.com",
			expectErr: repository.ErrInvalidEmail,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := repository.CanonicalizeEmail(tc.input)
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
			if got != tc.want {
				t.Fatalf("expected %q, got %q", tc.want, got)
			}
		})
	}
}

func TestNewUser(t *testing.T) {
	t.Run("valid user creation", func(t *testing.T) {
		u, err := repository.NewUser(" Alice@Example.Com ", "Alice Wonderland")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if u.Email != "alice@example.com" {
			t.Fatalf("expected email to be canonicalized, got %q", u.Email)
		}
		if u.DisplayName != "Alice Wonderland" {
			t.Fatalf("expected display name %q, got %q", "Alice Wonderland", u.DisplayName)
		}
		if u.Status != repository.StatusActive {
			t.Fatalf("expected StatusActive, got %v", u.Status)
		}
		if u.ID.String() == "" {
			t.Fatal("expected valid UUID, got empty")
		}
		if u.CreatedAt.IsZero() || u.UpdatedAt.IsZero() {
			t.Fatal("expected non-zero timestamps")
		}
	})

	t.Run("empty display name rejected", func(t *testing.T) {
		_, err := repository.NewUser("alice@example.com", "   ")
		if !errors.Is(err, repository.ErrInvalidDisplayName) {
			t.Fatalf("expected ErrInvalidDisplayName, got %v", err)
		}
	})

	t.Run("display name exceeding 100 characters rejected", func(t *testing.T) {
		_, err := repository.NewUser("alice@example.com", strings.Repeat("A", 101))
		if !errors.Is(err, repository.ErrInvalidDisplayName) {
			t.Fatalf("expected ErrInvalidDisplayName, got %v", err)
		}
	})

	t.Run("invalid email rejected", func(t *testing.T) {
		_, err := repository.NewUser("invalid-email", "Alice")
		if !errors.Is(err, repository.ErrInvalidEmail) {
			t.Fatalf("expected ErrInvalidEmail, got %v", err)
		}
	})
}
