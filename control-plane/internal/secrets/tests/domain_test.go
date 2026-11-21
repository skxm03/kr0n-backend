package tests

import (
	"errors"
	"strings"
	"testing"

	"github.com/skxm03/kr0n-backend/control-plane/internal/secrets/domain"
)

func TestValidateEnvVarBatchAndEnvironment(t *testing.T) {
	// 1. Environment normalization
	if env, err := domain.NormalizeEnvironment(""); err != nil || env != "production" {
		t.Fatalf("expected empty environment to default to 'production', got (%q, %v)", env, err)
	}
	if env, err := domain.NormalizeEnvironment("  Preview-Env  "); err != nil || env != "preview-env" {
		t.Fatalf("expected 'preview-env', got (%q, %v)", env, err)
	}
	if _, err := domain.NormalizeEnvironment("bad/env:1"); !errors.Is(err, domain.ErrInvalidEnvironment) {
		t.Fatalf("expected ErrInvalidEnvironment, got %v", err)
	}

	// 2. Valid batch including empty string value ""
	cleaned, err := domain.ValidateEnvVarBatch([]domain.EnvVarInput{
		{Key: "DATABASE_URL", Value: "postgres://localhost:5432/app"},
		{Key: "EMPTY_ALLOWED", Value: ""},
		{Key: "_PRIVATE_FLAG", Value: "1"},
	})
	if err != nil || len(cleaned) != 3 {
		t.Fatalf("expected valid batch, got err=%v len=%d", err, len(cleaned))
	}

	// 3. Invalid key syntax (starts with digit, hyphen, dot)
	for _, badKey := range []string{"123_KEY", "MY-KEY", "MY.KEY", "KEY WITH SPACE", ""} {
		if _, err := domain.ValidateEnvVarBatch([]domain.EnvVarInput{{Key: badKey, Value: "x"}}); !errors.Is(err, domain.ErrInvalidEnvVarKey) {
			t.Fatalf("expected ErrInvalidEnvVarKey for %q, got %v", badKey, err)
		}
	}

	// 4. Reserved platform keys rejected
	for _, reserved := range []string{"PORT", "port", "KR0N_INTERNAL_TOKEN", "KUBERNETES_SERVICE_HOST", "PATH"} {
		if _, err := domain.ValidateEnvVarBatch([]domain.EnvVarInput{{Key: reserved, Value: "x"}}); !errors.Is(err, domain.ErrReservedEnvVarKey) {
			t.Fatalf("expected ErrReservedEnvVarKey for %q, got %v", reserved, err)
		}
	}

	// 5. Duplicate keys in single request rejected
	if _, err := domain.ValidateEnvVarBatch([]domain.EnvVarInput{
		{Key: "API_KEY", Value: "v1"},
		{Key: "API_KEY", Value: "v2"},
	}); !errors.Is(err, domain.ErrDuplicateEnvVarKey) {
		t.Fatalf("expected ErrDuplicateEnvVarKey, got %v", err)
	}

	// 6. Value exceeding 64KB rejected
	huge := strings.Repeat("a", domain.MaxEnvVarValueBytes+1)
	if _, err := domain.ValidateEnvVarBatch([]domain.EnvVarInput{{Key: "HUGE_VAR", Value: huge}}); !errors.Is(err, domain.ErrEnvVarValueTooLarge) {
		t.Fatalf("expected ErrEnvVarValueTooLarge, got %v", err)
	}
}
