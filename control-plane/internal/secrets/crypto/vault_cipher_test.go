package crypto_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/skxm03/kr0n-backend/control-plane/internal/secrets/crypto"
	"github.com/skxm03/kr0n-backend/control-plane/internal/secrets/domain"
)

func TestVaultCipher_EnvelopeWorkflow(t *testing.T) {
	rawKEK, err := crypto.GenerateRandomKey()
	if err != nil {
		t.Fatalf("GenerateRandomKey: %v", err)
	}
	km, err := crypto.NewKeyManager(rawKEK, 1)
	if err != nil {
		t.Fatalf("NewKeyManager: %v", err)
	}

	cipher := crypto.NewEnvelopeCipher(km)
	projID := uuid.New()
	env := "production"

	// 1. Generate project key
	pk, dek, err := cipher.GenerateProjectKey(projID)
	if err != nil {
		t.Fatalf("GenerateProjectKey: %v", err)
	}
	if pk.ProjectID != projID || len(pk.EncryptedDEK) == 0 || pk.DEKVersion != 1 {
		t.Fatalf("invalid generated project key: %+v", pk)
	}

	// 2. Unwrap project key
	unwrappedDEK, err := cipher.UnwrapProjectKey(pk)
	if err != nil {
		t.Fatalf("UnwrapProjectKey: %v", err)
	}
	if !bytes.Equal(unwrappedDEK, dek) {
		t.Fatalf("unwrapped DEK does not match generated DEK")
	}

	// 3. Encrypt batch of env vars
	inputs := []domain.EnvVarInput{
		{Key: "DB_HOST", Value: "postgres.local"},
		{Key: "DB_PORT", Value: "5432"},
		{Key: "EMPTY_VAL", Value: ""},
	}
	records, err := cipher.EncryptEnvVars(projID, env, dek, pk.DEKVersion, inputs)
	if err != nil {
		t.Fatalf("EncryptEnvVars: %v", err)
	}
	if len(records) != 3 {
		t.Fatalf("expected 3 records, got %d", len(records))
	}

	// 4. Decrypt batch of env vars
	decrypted, err := cipher.DecryptEnvVars(projID, env, dek, records)
	if err != nil {
		t.Fatalf("DecryptEnvVars: %v", err)
	}
	if decrypted["DB_HOST"] != "postgres.local" || decrypted["DB_PORT"] != "5432" || decrypted["EMPTY_VAL"] != "" {
		t.Fatalf("unexpected decrypted values: %+v", decrypted)
	}

	// 5. Tamper AAD
	records[0].Key = "HIJACKED_KEY"
	if _, err := cipher.DecryptEnvVars(projID, env, dek, records); !errors.Is(err, crypto.ErrDecryptionFailed) {
		t.Fatalf("expected ErrDecryptionFailed on tampered key, got %v", err)
	}
}
