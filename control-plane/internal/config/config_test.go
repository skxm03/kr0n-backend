package config

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/skxm03/kr0n-backend/control-plane/internal/auth/jwtkeys"
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

func TestLoadGatewayFrom(t *testing.T) {
	t.Run("defaults when empty", func(t *testing.T) {
		lookup := func(key string) (string, bool) {
			return "", false
		}

		cfg, err := LoadGatewayFrom(lookup)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cfg.GatewayHTTPAddr != ":8080" {
			t.Fatalf("expected default :8080, got %q", cfg.GatewayHTTPAddr)
		}
		if cfg.AuthGRPCAddr != "localhost:50051" {
			t.Fatalf("expected default localhost:50051, got %q", cfg.AuthGRPCAddr)
		}
	})

	t.Run("custom values", func(t *testing.T) {
		env := map[string]string{
			"GATEWAY_HTTP_ADDR": ":9090",
			"AUTH_GRPC_ADDR":    "auth.internal:50051",
		}
		lookup := func(key string) (string, bool) {
			val, ok := env[key]
			return val, ok
		}

		cfg, err := LoadGatewayFrom(lookup)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cfg.GatewayHTTPAddr != ":9090" {
			t.Fatalf("expected :9090, got %q", cfg.GatewayHTTPAddr)
		}
		if cfg.AuthGRPCAddr != "auth.internal:50051" {
			t.Fatalf("expected auth.internal:50051, got %q", cfg.AuthGRPCAddr)
		}
	})
}

func TestLoad_EmailVerificationTokenLifetime(t *testing.T) {
	t.Run("default lifetime", func(t *testing.T) {
		lookup := func(key string) (string, bool) {
			if key == "DATABASE_URL" {
				return "postgres://user:pass@localhost:5432/db", true
			}
			return "", false
		}
		cfg, err := LoadFrom(lookup)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cfg.EmailVerificationTokenLifetime != 24*time.Hour {
			t.Fatalf("expected default 24h, got %v", cfg.EmailVerificationTokenLifetime)
		}
	})

	t.Run("custom lifetime", func(t *testing.T) {
		lookup := func(key string) (string, bool) {
			if key == "DATABASE_URL" {
				return "postgres://user:pass@localhost:5432/db", true
			}
			if key == "EMAIL_VERIFICATION_TOKEN_LIFETIME" {
				return "48h", true
			}
			return "", false
		}
		cfg, err := LoadFrom(lookup)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cfg.EmailVerificationTokenLifetime != 48*time.Hour {
			t.Fatalf("expected 48h, got %v", cfg.EmailVerificationTokenLifetime)
		}
	})

	t.Run("invalid lifetime duration", func(t *testing.T) {
		lookup := func(key string) (string, bool) {
			if key == "DATABASE_URL" {
				return "postgres://user:pass@localhost:5432/db", true
			}
			if key == "EMAIL_VERIFICATION_TOKEN_LIFETIME" {
				return "invalid", true
			}
			return "", false
		}
		_, err := LoadFrom(lookup)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
	})

	t.Run("negative lifetime duration", func(t *testing.T) {
		lookup := func(key string) (string, bool) {
			if key == "DATABASE_URL" {
				return "postgres://user:pass@localhost:5432/db", true
			}
			if key == "EMAIL_VERIFICATION_TOKEN_LIFETIME" {
				return "-1h", true
			}
			return "", false
		}
		_, err := LoadFrom(lookup)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
	})
}

func TestHardening_NonDevRefusesDefaultDevKeysAndPlaintextGRPC(t *testing.T) {
	devSeed := jwtkeys.DevPrivateKey().Seed()
	devPrivB64 := base64.StdEncoding.EncodeToString(devSeed)
	devPubB64 := base64.StdEncoding.EncodeToString(jwtkeys.DevPrivateKey().Public().(ed25519.PublicKey))

	pub, priv, _ := ed25519.GenerateKey(nil)
	prodPrivB64 := base64.StdEncoding.EncodeToString(priv.Seed())
	prodPubB64 := base64.StdEncoding.EncodeToString(pub)

	t.Run("auth refuses missing key outside dev", func(t *testing.T) {
		env := map[string]string{
			"DATABASE_URL": "postgres://u:p@localhost:5432/db",
			"KR0N_ENV":     "staging",
		}
		if _, err := LoadFrom(func(k string) (string, bool) { v, ok := env[k]; return v, ok }); err == nil {
			t.Fatal("expected error when JWT_PRIVATE_KEY unset in staging")
		}
	})

	t.Run("auth refuses default dev key outside dev", func(t *testing.T) {
		env := map[string]string{
			"DATABASE_URL":            "postgres://u:p@localhost:5432/db",
			"KR0N_ENV":                "production",
			"JWT_PRIVATE_KEY":         devPrivB64,
			"AUTH_GRPC_TLS_CERT_FILE": "/etc/tls/tls.crt",
			"AUTH_GRPC_TLS_KEY_FILE":  "/etc/tls/tls.key",
		}
		if _, err := LoadFrom(func(k string) (string, bool) { v, ok := env[k]; return v, ok }); err == nil {
			t.Fatal("expected error when default dev private key is passed in production")
		}
	})

	t.Run("auth refuses plaintext gRPC outside dev", func(t *testing.T) {
		env := map[string]string{
			"DATABASE_URL":    "postgres://u:p@localhost:5432/db",
			"KR0N_ENV":        "production",
			"JWT_PRIVATE_KEY": prodPrivB64,
		}
		if _, err := LoadFrom(func(k string) (string, bool) { v, ok := env[k]; return v, ok }); err == nil {
			t.Fatal("expected error when TLS cert/key unset in production")
		}
	})

	t.Run("auth succeeds outside dev with real key and TLS cert/key", func(t *testing.T) {
		env := map[string]string{
			"DATABASE_URL":            "postgres://u:p@localhost:5432/db",
			"KR0N_ENV":                "production",
			"JWT_PRIVATE_KEY":         prodPrivB64,
			"AUTH_GRPC_TLS_CERT_FILE": "/etc/tls/tls.crt",
			"AUTH_GRPC_TLS_KEY_FILE":  "/etc/tls/tls.key",
		}
		cfg, err := LoadFrom(func(k string) (string, bool) { v, ok := env[k]; return v, ok })
		if err != nil || cfg.AuthGRPCTLSCertFile == "" {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("gateway refuses default dev public key outside dev", func(t *testing.T) {
		env := map[string]string{
			"KR0N_ENV":        "production",
			"JWT_PUBLIC_KEYS": "k1:" + devPubB64,
		}
		if _, err := LoadGatewayFrom(func(k string) (string, bool) { v, ok := env[k]; return v, ok }); err == nil {
			t.Fatal("expected error when default dev public key is passed in production")
		}
	})

	t.Run("gateway disables plaintext gRPC outside dev", func(t *testing.T) {
		env := map[string]string{
			"KR0N_ENV":        "production",
			"JWT_PUBLIC_KEYS": "k1:" + prodPubB64,
		}
		cfg, err := LoadGatewayFrom(func(k string) (string, bool) { v, ok := env[k]; return v, ok })
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cfg.AuthGRPCTLSPlain {
			t.Fatal("expected AuthGRPCTLSPlain=false outside dev")
		}
	})
}
