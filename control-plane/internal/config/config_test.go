package config

import (
	"errors"
	"strings"
	"testing"
)

func TestLoadFrom(t *testing.T) {
	tests := []struct {
		name        string
		env         map[string]string
		hasVar      bool
		wantURL     string
		wantErr     error
		errContains string
	}{
		{
			name: "valid postgres URL",
			env: map[string]string{
				"DATABASE_URL": "postgres://kr0n:kr0n_dev_password@localhost:5432/kr0n",
			},
			hasVar:  true,
			wantURL: "postgres://kr0n:kr0n_dev_password@localhost:5432/kr0n",
		},
		{
			name: "valid postgresql URL with query parameters",
			env: map[string]string{
				"DATABASE_URL": "postgresql://kr0n:kr0n_dev_password@localhost:5432/kr0n?sslmode=disable",
			},
			hasVar:  true,
			wantURL: "postgresql://kr0n:kr0n_dev_password@localhost:5432/kr0n?sslmode=disable",
		},
		{
			name: "valid URL with surrounding whitespace trimmed",
			env: map[string]string{
				"DATABASE_URL": "  postgres://kr0n:kr0n_dev_password@localhost:5432/kr0n  \n",
			},
			hasVar:  true,
			wantURL: "postgres://kr0n:kr0n_dev_password@localhost:5432/kr0n",
		},
		{
			name:    "missing DATABASE_URL",
			env:     map[string]string{},
			hasVar:  false,
			wantErr: ErrMissingDatabaseURL,
		},
		{
			name: "empty DATABASE_URL",
			env: map[string]string{
				"DATABASE_URL": "",
			},
			hasVar:  true,
			wantErr: ErrEmptyDatabaseURL,
		},
		{
			name: "whitespace-only DATABASE_URL",
			env: map[string]string{
				"DATABASE_URL": "   \t \n ",
			},
			hasVar:  true,
			wantErr: ErrEmptyDatabaseURL,
		},
		{
			name: "invalid scheme http",
			env: map[string]string{
				"DATABASE_URL": "http://localhost:5432/kr0n",
			},
			hasVar:      true,
			wantErr:     ErrInvalidDatabaseURL,
			errContains: "scheme must be postgres:// or postgresql://",
		},
		{
			name: "invalid scheme mysql",
			env: map[string]string{
				"DATABASE_URL": "mysql://user:pass@localhost:3306/kr0n",
			},
			hasVar:      true,
			wantErr:     ErrInvalidDatabaseURL,
			errContains: "scheme must be postgres:// or postgresql://",
		},
		{
			name: "missing scheme",
			env: map[string]string{
				"DATABASE_URL": "localhost:5432/kr0n",
			},
			hasVar:      true,
			wantErr:     ErrInvalidDatabaseURL,
			errContains: "scheme must be postgres:// or postgresql://",
		},
		{
			name: "missing host",
			env: map[string]string{
				"DATABASE_URL": "postgres://",
			},
			hasVar:      true,
			wantErr:     ErrInvalidDatabaseURL,
			errContains: "missing host",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			lookup := func(key string) (string, bool) {
				if !tc.hasVar {
					return "", false
				}
				val, ok := tc.env[key]
				return val, ok
			}

			cfg, err := LoadFrom(lookup)
			if tc.wantErr != nil {
				if err == nil {
					t.Fatalf("expected error wrapping %v, got nil", tc.wantErr)
				}
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("expected error wrapping %v, got %v", tc.wantErr, err)
				}
				if tc.errContains != "" && !strings.Contains(err.Error(), tc.errContains) {
					t.Fatalf("expected error containing %q, got %q", tc.errContains, err.Error())
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if cfg == nil {
				t.Fatal("expected non-nil config")
			}
			if cfg.DatabaseURL != tc.wantURL {
				t.Fatalf("expected DatabaseURL %q, got %q", tc.wantURL, cfg.DatabaseURL)
			}
		})
	}
}

func TestLoad_Environment(t *testing.T) {
	t.Run("successful load from environment", func(t *testing.T) {
		const expectedURL = "postgres://kr0n:kr0n_dev_password@localhost:5432/kr0n"
		t.Setenv("DATABASE_URL", expectedURL)

		cfg, err := Load()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cfg == nil {
			t.Fatal("expected non-nil config")
		}
		if cfg.DatabaseURL != expectedURL {
			t.Fatalf("expected %q, got %q", expectedURL, cfg.DatabaseURL)
		}
	})

	t.Run("empty environment variable fails", func(t *testing.T) {
		t.Setenv("DATABASE_URL", "")

		_, err := Load()
		if err == nil {
			t.Fatal("expected error for empty DATABASE_URL, got nil")
		}
		if !errors.Is(err, ErrEmptyDatabaseURL) {
			t.Fatalf("expected ErrEmptyDatabaseURL, got %v", err)
		}
	})
}
