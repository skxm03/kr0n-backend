package user

import (
	"errors"
	"strings"
	"testing"
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
			expectErr: ErrInvalidEmail,
		},
		{
			name:      "whitespace only email",
			input:     "    ",
			expectErr: ErrInvalidEmail,
		},
		{
			name:      "missing at-sign",
			input:     "userexample.com",
			expectErr: ErrInvalidEmail,
		},
		{
			name:      "missing domain",
			input:     "user@",
			expectErr: ErrInvalidEmail,
		},
		{
			name:      "embedded newline or carriage return",
			input:     "user\r\n@example.com",
			expectErr: ErrInvalidEmail,
		},
		{
			name:      "formatted display name not permitted",
			input:     "Alice Wonderland <alice@example.com>",
			expectErr: ErrInvalidEmail,
		},
		{
			name:      "exceeds RFC max length 254 bytes",
			input:     strings.Repeat("a", 250) + "@domain.com",
			expectErr: ErrInvalidEmail,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := CanonicalizeEmail(tc.input)
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
		u, err := NewUser(" Alice@Example.Com ", "Alice Wonderland")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if u.Email != "alice@example.com" {
			t.Fatalf("expected email to be canonicalized, got %q", u.Email)
		}
		if u.DisplayName != "Alice Wonderland" {
			t.Fatalf("expected display name %q, got %q", "Alice Wonderland", u.DisplayName)
		}
		if u.Status != StatusActive {
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
		_, err := NewUser("alice@example.com", "   ")
		if !errors.Is(err, ErrInvalidDisplayName) {
			t.Fatalf("expected ErrInvalidDisplayName, got %v", err)
		}
	})

	t.Run("display name exceeding 100 characters rejected", func(t *testing.T) {
		_, err := NewUser("alice@example.com", strings.Repeat("A", 101))
		if !errors.Is(err, ErrInvalidDisplayName) {
			t.Fatalf("expected ErrInvalidDisplayName, got %v", err)
		}
	})

	t.Run("invalid email rejected", func(t *testing.T) {
		_, err := NewUser("invalid-email", "Alice")
		if !errors.Is(err, ErrInvalidEmail) {
			t.Fatalf("expected ErrInvalidEmail, got %v", err)
		}
	})
}
