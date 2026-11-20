package webhook

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
)

func signPayload(secret string, payload []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

func TestVerifyGitHubSignature(t *testing.T) {
	secret := "whsec_test_github_secret_123"
	payload := []byte(`{"action":"deleted","installation":{"id":987654,"account":{"login":"kr0n-org","type":"Organization"}}}`)
	validSig := signPayload(secret, payload)

	t.Run("valid signature passes", func(t *testing.T) {
		if err := VerifyGitHubSignature(payload, validSig, secret); err != nil {
			t.Fatalf("expected valid signature, got: %v", err)
		}
	})

	t.Run("empty secret fails", func(t *testing.T) {
		if err := VerifyGitHubSignature(payload, validSig, ""); !errors.Is(err, ErrWebhookSecretNotConfigured) {
			t.Fatalf("expected ErrWebhookSecretNotConfigured, got: %v", err)
		}
	})

	t.Run("missing signature header fails", func(t *testing.T) {
		if err := VerifyGitHubSignature(payload, "", secret); !errors.Is(err, ErrMissingSignature) {
			t.Fatalf("expected ErrMissingSignature, got: %v", err)
		}
	})

	t.Run("wrong algorithm prefix fails", func(t *testing.T) {
		badPrefix := "sha1=" + validSig[len("sha256="):]
		if err := VerifyGitHubSignature(payload, badPrefix, secret); !errors.Is(err, ErrInvalidSignature) {
			t.Fatalf("expected ErrInvalidSignature, got: %v", err)
		}
	})

	t.Run("non-hex signature fails", func(t *testing.T) {
		if err := VerifyGitHubSignature(payload, "sha256=not-valid-hex!!", secret); !errors.Is(err, ErrInvalidSignature) {
			t.Fatalf("expected ErrInvalidSignature, got: %v", err)
		}
	})

	t.Run("tampered payload fails", func(t *testing.T) {
		tampered := []byte(`{"action":"deleted","installation":{"id":987655,"account":{"login":"kr0n-org","type":"Organization"}}}`)
		if err := VerifyGitHubSignature(tampered, validSig, secret); !errors.Is(err, ErrInvalidSignature) {
			t.Fatalf("expected ErrInvalidSignature for tampered payload, got: %v", err)
		}
	})

	t.Run("wrong secret fails", func(t *testing.T) {
		if err := VerifyGitHubSignature(payload, validSig, "wrong_secret"); !errors.Is(err, ErrInvalidSignature) {
			t.Fatalf("expected ErrInvalidSignature for wrong secret, got: %v", err)
		}
	})
}
