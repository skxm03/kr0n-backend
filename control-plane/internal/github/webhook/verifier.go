package webhook

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"strings"
)

var (
	// ErrWebhookSecretNotConfigured indicates GITHUB_WEBHOOK_SECRET is empty.
	ErrWebhookSecretNotConfigured = errors.New("webhook secret not configured")
	// ErrMissingSignature indicates the X-Hub-Signature-256 header is absent.
	ErrMissingSignature = errors.New("missing X-Hub-Signature-256 header")
	// ErrInvalidSignature indicates the HMAC-SHA256 signature is malformed or does not match payload.
	ErrInvalidSignature = errors.New("invalid webhook signature")
)

// VerifyGitHubSignature validates GitHub's X-Hub-Signature-256 ("sha256=<hex>") header
// against the raw request payload bytes using constant-time comparison.
func VerifyGitHubSignature(payload []byte, signatureHeader, secret string) error {
	if secret == "" {
		return ErrWebhookSecretNotConfigured
	}
	if signatureHeader == "" {
		return ErrMissingSignature
	}

	parts := strings.SplitN(signatureHeader, "=", 2)
	if len(parts) != 2 || parts[0] != "sha256" {
		return ErrInvalidSignature
	}

	sigBytes, err := hex.DecodeString(parts[1])
	if err != nil {
		return ErrInvalidSignature
	}

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	expectedMAC := mac.Sum(nil)

	if subtle.ConstantTimeCompare(sigBytes, expectedMAC) != 1 {
		return ErrInvalidSignature
	}
	return nil
}
