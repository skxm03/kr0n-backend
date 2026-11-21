package crypto

import (
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/uuid"
)

// KeyManager wraps and unwraps per-project Data Encryption Keys (DEKs) using the Master Key Encryption Key (KEK),
// as well as encrypting and decrypting individual secret values with Associated Authenticated Data (AAD).
type KeyManager struct {
	masterKEK  []byte
	kekVersion int
}

// NewKeyManager constructs a KeyManager from a raw 32-byte master KEK and version number.
func NewKeyManager(masterKEK []byte, version int) (*KeyManager, error) {
	if len(masterKEK) != AES256KeySize {
		return nil, ErrInvalidKeySize
	}
	if version <= 0 {
		version = 1
	}
	cp := make([]byte, AES256KeySize)
	copy(cp, masterKEK)
	return &KeyManager{
		masterKEK:  cp,
		kekVersion: version,
	}, nil
}

// NewKeyManagerFromPath loads a 64-character hex-encoded 32-byte Master KEK from disk.
// If path is relative and not found in the current working directory, it also checks `../<path>`.
func NewKeyManagerFromPath(path string, version int) (*KeyManager, error) {
	trimmedPath := strings.TrimSpace(path)
	if trimmedPath == "" {
		return nil, errors.New("master KEK path is empty")
	}

	raw, err := os.ReadFile(trimmedPath)
	if err != nil && !filepath.IsAbs(trimmedPath) {
		if alt, altErr := os.ReadFile(filepath.Join("..", trimmedPath)); altErr == nil {
			raw = alt
			err = nil
		}
	}
	if err != nil {
		return nil, fmt.Errorf("read master KEK file: %w", err)
	}

	clean := strings.TrimSpace(string(raw))
	key, err := hex.DecodeString(clean)
	if err != nil {
		return nil, errors.New("decode master KEK: file does not contain valid hexadecimal characters")
	}
	if len(key) != AES256KeySize {
		return nil, fmt.Errorf("master KEK must be exactly %d bytes (64 hex characters), got %d bytes", AES256KeySize, len(key))
	}

	return NewKeyManager(key, version)
}

// KEKVersion returns the active Master KEK version number.
func (km *KeyManager) KEKVersion() int {
	if km == nil || km.kekVersion <= 0 {
		return 1
	}
	return km.kekVersion
}

// DEKAAD constructs Associated Authenticated Data binding a wrapped DEK to its owning projectID.
func DEKAAD(projectID uuid.UUID) []byte {
	return []byte(projectID.String() + ":project-dek")
}

// SecretAAD constructs Associated Authenticated Data binding an encrypted secret value to its project, environment, and key name.
func SecretAAD(projectID uuid.UUID, environment, secretKey string) []byte {
	return []byte(projectID.String() + ":" + environment + ":" + secretKey)
}

// WrapDEK encrypts a 32-byte project DEK using the Master KEK and project-bound AAD.
func (km *KeyManager) WrapDEK(projectID uuid.UUID, dek []byte) (encryptedDEK, nonce []byte, err error) {
	if km == nil || len(km.masterKEK) != AES256KeySize {
		return nil, nil, ErrInvalidKeySize
	}
	if len(dek) != AES256KeySize {
		return nil, nil, ErrInvalidKeySize
	}
	return EncryptGCM(km.masterKEK, dek, DEKAAD(projectID))
}

// UnwrapDEK decrypts and authenticates a project DEK using the Master KEK and project-bound AAD.
func (km *KeyManager) UnwrapDEK(projectID uuid.UUID, encryptedDEK, nonce []byte) ([]byte, error) {
	if km == nil || len(km.masterKEK) != AES256KeySize {
		return nil, ErrInvalidKeySize
	}
	return DecryptGCM(km.masterKEK, encryptedDEK, nonce, DEKAAD(projectID))
}

// EncryptSecret encrypts a secret plaintext value using a 32-byte project DEK and AAD bound to (projectID, environment, secretKey).
func EncryptSecret(dek []byte, projectID uuid.UUID, environment, secretKey, plaintext string) (ciphertext, nonce []byte, err error) {
	aad := SecretAAD(projectID, environment, secretKey)
	return EncryptGCM(dek, []byte(plaintext), aad)
}

// DecryptSecret decrypts and authenticates a secret value using a 32-byte project DEK and AAD bound to (projectID, environment, secretKey).
func DecryptSecret(dek []byte, projectID uuid.UUID, environment, secretKey string, ciphertext, nonce []byte) (string, error) {
	aad := SecretAAD(projectID, environment, secretKey)
	plain, err := DecryptGCM(dek, ciphertext, nonce, aad)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}
