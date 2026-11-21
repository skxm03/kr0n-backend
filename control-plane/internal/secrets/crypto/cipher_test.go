package crypto_test

import (
	"bytes"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/uuid"

	"github.com/skxm03/kr0n-backend/control-plane/internal/secrets/crypto"
)

func TestEncryptDecryptGCM_RoundtripAndEmptyPlaintext(t *testing.T) {
	key, err := crypto.GenerateRandomKey()
	if err != nil {
		t.Fatalf("GenerateRandomKey: %v", err)
	}
	aad := []byte("proj-1:production:DATABASE_URL")

	ct, nonce, err := crypto.EncryptGCM(key, []byte("postgres://user:pass@db:5432/app"), aad)
	if err != nil {
		t.Fatalf("EncryptGCM: %v", err)
	}
	pt, err := crypto.DecryptGCM(key, ct, nonce, aad)
	if err != nil {
		t.Fatalf("DecryptGCM: %v", err)
	}
	if string(pt) != "postgres://user:pass@db:5432/app" {
		t.Fatalf("unexpected plaintext: %q", string(pt))
	}

	ctEmpty, nonceEmpty, err := crypto.EncryptGCM(key, []byte(""), aad)
	if err != nil {
		t.Fatalf("EncryptGCM empty: %v", err)
	}
	ptEmpty, err := crypto.DecryptGCM(key, ctEmpty, nonceEmpty, aad)
	if err != nil {
		t.Fatalf("DecryptGCM empty: %v", err)
	}
	if ptEmpty == nil || len(ptEmpty) != 0 {
		t.Fatalf("expected non-nil empty slice, got %v", ptEmpty)
	}
}

func TestEncryptDecryptGCM_TamperingAndAADMismatch(t *testing.T) {
	key, err := crypto.GenerateRandomKey()
	if err != nil {
		t.Fatalf("GenerateRandomKey: %v", err)
	}
	aad := []byte("proj-1:production:JWT_SECRET")
	ct, nonce, err := crypto.EncryptGCM(key, []byte("super-secret-jwt-key"), aad)
	if err != nil {
		t.Fatalf("EncryptGCM: %v", err)
	}

	tamperedCT := append([]byte(nil), ct...)
	tamperedCT[0] ^= 0xFF
	if _, err := crypto.DecryptGCM(key, tamperedCT, nonce, aad); !errors.Is(err, crypto.ErrDecryptionFailed) {
		t.Fatalf("expected ErrDecryptionFailed for tampered ciphertext, got %v", err)
	}

	tamperedNonce := append([]byte(nil), nonce...)
	tamperedNonce[0] ^= 0xFF
	if _, err := crypto.DecryptGCM(key, ct, tamperedNonce, aad); !errors.Is(err, crypto.ErrDecryptionFailed) {
		t.Fatalf("expected ErrDecryptionFailed for tampered nonce, got %v", err)
	}

	wrongProjectAAD := []byte("proj-2:production:JWT_SECRET")
	if _, err := crypto.DecryptGCM(key, ct, nonce, wrongProjectAAD); !errors.Is(err, crypto.ErrDecryptionFailed) {
		t.Fatalf("expected ErrDecryptionFailed for wrong project AAD, got %v", err)
	}
	wrongEnvAAD := []byte("proj-1:staging:JWT_SECRET")
	if _, err := crypto.DecryptGCM(key, ct, nonce, wrongEnvAAD); !errors.Is(err, crypto.ErrDecryptionFailed) {
		t.Fatalf("expected ErrDecryptionFailed for wrong environment AAD, got %v", err)
	}
	wrongKeyNameAAD := []byte("proj-1:production:OTHER_SECRET")
	if _, err := crypto.DecryptGCM(key, ct, nonce, wrongKeyNameAAD); !errors.Is(err, crypto.ErrDecryptionFailed) {
		t.Fatalf("expected ErrDecryptionFailed for wrong key name AAD, got %v", err)
	}

	if _, _, err := crypto.EncryptGCM([]byte("short-key"), []byte("x"), aad); !errors.Is(err, crypto.ErrInvalidKeySize) {
		t.Fatalf("expected ErrInvalidKeySize, got %v", err)
	}
}

func TestKeyManager_WrapUnwrapDEKAndSecretAADBinding(t *testing.T) {
	kek, err := crypto.GenerateRandomKey()
	if err != nil {
		t.Fatalf("GenerateRandomKey: %v", err)
	}
	tmpDir := t.TempDir()
	kekPath := filepath.Join(tmpDir, "kr0n-kek.key")
	if err := os.WriteFile(kekPath, []byte(hex.EncodeToString(kek)+"\n"), 0o600); err != nil {
		t.Fatalf("write kek file: %v", err)
	}

	km, err := crypto.NewKeyManagerFromPath(kekPath, 2)
	if err != nil {
		t.Fatalf("NewKeyManagerFromPath: %v", err)
	}
	if km.KEKVersion() != 2 {
		t.Fatalf("expected KEKVersion 2, got %d", km.KEKVersion())
	}

	projA := uuid.New()
	projB := uuid.New()
	dek, err := crypto.GenerateRandomKey()
	if err != nil {
		t.Fatalf("generate DEK: %v", err)
	}

	encDEK, nonce, err := km.WrapDEK(projA, dek)
	if err != nil {
		t.Fatalf("WrapDEK: %v", err)
	}

	unwrapped, err := km.UnwrapDEK(projA, encDEK, nonce)
	if err != nil {
		t.Fatalf("UnwrapDEK: %v", err)
	}
	if !bytes.Equal(unwrapped, dek) {
		t.Fatal("unwrapped DEK does not match original DEK")
	}

	if _, err := km.UnwrapDEK(projB, encDEK, nonce); !errors.Is(err, crypto.ErrDecryptionFailed) {
		t.Fatalf("expected ErrDecryptionFailed when unwrapping DEK for wrong project, got %v", err)
	}

	ct, sNonce, err := crypto.EncryptSecret(dek, projA, "production", "STRIPE_KEY", "sk_live_12345")
	if err != nil {
		t.Fatalf("EncryptSecret: %v", err)
	}
	val, err := crypto.DecryptSecret(dek, projA, "production", "STRIPE_KEY", ct, sNonce)
	if err != nil || val != "sk_live_12345" {
		t.Fatalf("DecryptSecret: err=%v val=%q", err, val)
	}

	if _, err := crypto.DecryptSecret(dek, projA, "preview", "STRIPE_KEY", ct, sNonce); !errors.Is(err, crypto.ErrDecryptionFailed) {
		t.Fatalf("expected ErrDecryptionFailed for cross-environment secret decryption, got %v", err)
	}
}
