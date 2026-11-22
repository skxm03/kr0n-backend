package crypto

import (
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/skxm03/kr0n-backend/control-plane/internal/secrets/domain"
)

// VaultCipher defines cryptographic transformations for project keys and environment variable secrets.
// It is completely decoupled from any database persistence mechanism.
type VaultCipher interface {
	// GenerateProjectKey creates a cryptographically random DEK, wraps it under the Master KEK,
	// and returns an unpersisted domain.ProjectKey together with the raw 32-byte DEK.
	GenerateProjectKey(projectID uuid.UUID) (*domain.ProjectKey, []byte, error)

	// UnwrapProjectKey decrypts and authenticates an encrypted domain.ProjectKey using the Master KEK.
	UnwrapProjectKey(key *domain.ProjectKey) ([]byte, error)

	// EncryptEnvVars encrypts plaintext environment variable inputs with AES-256-GCM and AAD bound
	// to (projectID, environment, key), returning domain.ProjectEnvVar ciphertext records.
	EncryptEnvVars(projectID uuid.UUID, environment string, dek []byte, dekVersion int, inputs []domain.EnvVarInput) ([]domain.ProjectEnvVar, error)

	// DecryptEnvVars decrypts domain.ProjectEnvVar ciphertext records with AES-256-GCM and verifies AAD,
	// returning a map of plaintext key-value pairs.
	DecryptEnvVars(projectID uuid.UUID, environment string, dek []byte, records []domain.ProjectEnvVar) (map[string]string, error)
}

// EnvelopeCipher implements VaultCipher using a Master KEK KeyManager.
type EnvelopeCipher struct {
	km *KeyManager
}

// NewEnvelopeCipher creates an EnvelopeCipher wrapping the provided KeyManager.
func NewEnvelopeCipher(km *KeyManager) *EnvelopeCipher {
	return &EnvelopeCipher{km: km}
}

// GenerateProjectKey creates a fresh random DEK, wraps it with master KEK and project AAD,
// and returns both the domain.ProjectKey and the raw DEK bytes.
func (c *EnvelopeCipher) GenerateProjectKey(projectID uuid.UUID) (*domain.ProjectKey, []byte, error) {
	if c == nil || c.km == nil {
		return nil, nil, domain.ErrMasterKeyNotConfigured
	}
	dek, err := GenerateRandomKey()
	if err != nil {
		return nil, nil, fmt.Errorf("generate random dek: %w", err)
	}
	encDEK, nonce, err := c.km.WrapDEK(projectID, dek)
	if err != nil {
		return nil, nil, fmt.Errorf("wrap dek: %w", err)
	}
	now := time.Now().UTC()
	pk := &domain.ProjectKey{
		ProjectID:    projectID,
		EncryptedDEK: encDEK,
		Nonce:        nonce,
		DEKVersion:   1,
		KEKVersion:   c.km.KEKVersion(),
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	return pk, dek, nil
}

// UnwrapProjectKey unwraps and authenticates a domain.ProjectKey using the Master KEK.
func (c *EnvelopeCipher) UnwrapProjectKey(key *domain.ProjectKey) ([]byte, error) {
	if c == nil || c.km == nil {
		return nil, domain.ErrMasterKeyNotConfigured
	}
	if key == nil {
		return nil, domain.ErrProjectKeyNotFound
	}
	return c.km.UnwrapDEK(key.ProjectID, key.EncryptedDEK, key.Nonce)
}

// EncryptEnvVars encrypts plaintext inputs into domain.ProjectEnvVar records.
func (c *EnvelopeCipher) EncryptEnvVars(
	projectID uuid.UUID,
	environment string,
	dek []byte,
	dekVersion int,
	inputs []domain.EnvVarInput,
) ([]domain.ProjectEnvVar, error) {
	now := time.Now().UTC()
	out := make([]domain.ProjectEnvVar, 0, len(inputs))
	for _, in := range inputs {
		ct, nonce, err := EncryptSecret(dek, projectID, environment, in.Key, in.Value)
		if err != nil {
			return nil, fmt.Errorf("encrypt secret %q: %w", in.Key, err)
		}
		out = append(out, domain.ProjectEnvVar{
			ID:             uuid.New(),
			ProjectID:      projectID,
			Environment:    environment,
			Key:            in.Key,
			EncryptedValue: ct,
			Nonce:          nonce,
			DEKVersion:     dekVersion,
			CreatedAt:      now,
			UpdatedAt:      now,
		})
	}
	return out, nil
}

// DecryptEnvVars decrypts domain.ProjectEnvVar records into plaintext key-value pairs.
func (c *EnvelopeCipher) DecryptEnvVars(
	projectID uuid.UUID,
	environment string,
	dek []byte,
	records []domain.ProjectEnvVar,
) (map[string]string, error) {
	out := make(map[string]string, len(records))
	for _, r := range records {
		plain, err := DecryptSecret(dek, projectID, environment, r.Key, r.EncryptedValue, r.Nonce)
		if err != nil {
			return nil, fmt.Errorf("decrypt secret %q: %w", r.Key, err)
		}
		out[r.Key] = plain
	}
	return out, nil
}

// Ensure KeyManager directly satisfies VaultCipher as well for maximum ergonomics.
var _ VaultCipher = (*EnvelopeCipher)(nil)
var _ VaultCipher = (*KeyManager)(nil)

func (km *KeyManager) GenerateProjectKey(projectID uuid.UUID) (*domain.ProjectKey, []byte, error) {
	return NewEnvelopeCipher(km).GenerateProjectKey(projectID)
}

func (km *KeyManager) UnwrapProjectKey(key *domain.ProjectKey) ([]byte, error) {
	return NewEnvelopeCipher(km).UnwrapProjectKey(key)
}

func (km *KeyManager) EncryptEnvVars(projectID uuid.UUID, environment string, dek []byte, dekVersion int, inputs []domain.EnvVarInput) ([]domain.ProjectEnvVar, error) {
	return NewEnvelopeCipher(km).EncryptEnvVars(projectID, environment, dek, dekVersion, inputs)
}

func (km *KeyManager) DecryptEnvVars(projectID uuid.UUID, environment string, dek []byte, records []domain.ProjectEnvVar) (map[string]string, error) {
	return NewEnvelopeCipher(km).DecryptEnvVars(projectID, environment, dek, records)
}
