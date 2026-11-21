package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
)

const AES256KeySize = 32

var (
	ErrInvalidKeySize   = errors.New("key must be exactly 32 bytes for AES-256")
	ErrDecryptionFailed = errors.New("decryption failed or authentication tag mismatch")
)

// GenerateRandomKey generates a cryptographically random 32-byte AES-256 key.
func GenerateRandomKey() ([]byte, error) {
	key := make([]byte, AES256KeySize)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, fmt.Errorf("read random bytes: %w", err)
	}
	return key, nil
}

// EncryptGCM encrypts plaintext using AES-256-GCM with the provided 32-byte key and Associated Authenticated Data (AAD).
// It generates a fresh 12-byte random nonce per invocation and returns (ciphertext, nonce, nil).
func EncryptGCM(key, plaintext, aad []byte) (ciphertext, nonce []byte, err error) {
	if len(key) != AES256KeySize {
		return nil, nil, ErrInvalidKeySize
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, fmt.Errorf("create aes cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, fmt.Errorf("create gcm: %w", err)
	}
	nonce = make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, fmt.Errorf("read random nonce: %w", err)
	}
	ciphertext = gcm.Seal(nil, nonce, plaintext, aad)
	return ciphertext, nonce, nil
}

// DecryptGCM decrypts and authenticates ciphertext using AES-256-GCM with the provided 32-byte key, nonce, and AAD.
// Never includes key material or plaintext in error messages.
func DecryptGCM(key, ciphertext, nonce, aad []byte) ([]byte, error) {
	if len(key) != AES256KeySize {
		return nil, ErrInvalidKeySize
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create aes cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create gcm: %w", err)
	}
	if len(nonce) != gcm.NonceSize() {
		return nil, ErrDecryptionFailed
	}
	plaintext, err := gcm.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, ErrDecryptionFailed
	}
	if plaintext == nil {
		plaintext = []byte{}
	}
	return plaintext, nil
}
