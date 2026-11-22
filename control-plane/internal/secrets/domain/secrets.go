package domain

import (
	"errors"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
)

const (
	MaskedSecretPlaceholder = "••••••••"
	DefaultEnvironment      = "production"
	MaxEnvVarKeyLength      = 256
	MaxEnvVarValueBytes     = 64 * 1024 // 64 KB
	MaxEnvVarBatchSize      = 100
)

var (
	ErrProjectNotFound        = errors.New("project not found")
	ErrForbidden              = errors.New("insufficient permissions")
	ErrEnvVarNotFound         = errors.New("environment variable not found")
	ErrInvalidEnvVarKey       = errors.New("invalid environment variable key: must match ^[a-zA-Z_][a-zA-Z0-9_]*$ and be 1..256 characters")
	ErrReservedEnvVarKey      = errors.New("environment variable key is reserved by the platform")
	ErrEnvVarValueTooLarge    = errors.New("environment variable value exceeds maximum length of 64KB")
	ErrDuplicateEnvVarKey     = errors.New("duplicate environment variable key in request")
	ErrEnvVarBatchLimit       = errors.New("environment variable batch must contain between 1 and 100 items")
	ErrInvalidEnvironment     = errors.New("invalid environment name")
	ErrMasterKeyNotConfigured = errors.New("project secret management is not configured: master KEK is missing")
	ErrProjectKeyNotFound     = errors.New("project key not found")
)

var (
	envVarKeyRegex       = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)
	environmentNameRegex = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*$`)
)

var reservedExactKeys = map[string]struct{}{
	"PORT":     {},
	"HOSTNAME": {},
	"HOME":     {},
	"PATH":     {},
	"PWD":      {},
}

var reservedKeyPrefixes = []string{
	"KR0N_",
	"KUBERNETES_",
}

// Principal represents an authenticated caller forwarded by the API Gateway via CallerPrincipal.
type Principal struct {
	UserID           uuid.UUID
	SessionID        *uuid.UUID
	Kind             string
	TokenOrgID       *uuid.UUID
	TokenPermissions []string
}

// ProjectKey represents an encrypted per-project Data Encryption Key (DEK) in `project_keys`.
type ProjectKey struct {
	ProjectID    uuid.UUID
	EncryptedDEK []byte
	Nonce        []byte
	DEKVersion   int
	KEKVersion   int
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// ProjectEnvVar represents an encrypted environment variable row in `project_env_vars`.
type ProjectEnvVar struct {
	ID             uuid.UUID
	ProjectID      uuid.UUID
	Environment    string
	Key            string
	EncryptedValue []byte
	Nonce          []byte
	DEKVersion     int
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// EnvVarInput holds a plaintext key-value pair submitted for encryption and storage.
type EnvVarInput struct {
	Key   string
	Value string
}

// EnvVarMetadata represents the write-only public projection of a stored project secret.
// Raw plaintext is never exposed here; MaskedValue is always "••••••••" and HasValue is true.
type EnvVarMetadata struct {
	ID          uuid.UUID
	ProjectID   uuid.UUID
	Environment string
	Key         string
	MaskedValue string
	HasValue    bool
	DEKVersion  int
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// NormalizeEnvironment canonicalizes an environment string (defaulting empty to "production")
// and validates that it is a clean lowercase slug (e.g., "production", "staging", "preview", "development").
func NormalizeEnvironment(raw string) (string, error) {
	env := strings.ToLower(strings.TrimSpace(raw))
	if env == "" {
		return DefaultEnvironment, nil
	}
	if len(env) > 63 || !environmentNameRegex.MatchString(env) {
		return "", ErrInvalidEnvironment
	}
	return env, nil
}

// ValidateEnvVarKey verifies that key matches POSIX identifier rules and is not a reserved platform variable.
func ValidateEnvVarKey(key string) error {
	if len(key) < 1 || len(key) > MaxEnvVarKeyLength || !envVarKeyRegex.MatchString(key) {
		return ErrInvalidEnvVarKey
	}
	upper := strings.ToUpper(key)
	if _, reserved := reservedExactKeys[upper]; reserved {
		return ErrReservedEnvVarKey
	}
	for _, prefix := range reservedKeyPrefixes {
		if strings.HasPrefix(upper, prefix) {
			return ErrReservedEnvVarKey
		}
	}
	return nil
}

// ValidateEnvVarBatch validates a slice of EnvVarInput items for size limits, valid keys, reserved keys,
// value length limits (allowing empty strings ""), and duplicate keys within the same batch.
func ValidateEnvVarBatch(inputs []EnvVarInput) ([]EnvVarInput, error) {
	if len(inputs) == 0 || len(inputs) > MaxEnvVarBatchSize {
		return nil, ErrEnvVarBatchLimit
	}
	seen := make(map[string]struct{}, len(inputs))
	cleaned := make([]EnvVarInput, 0, len(inputs))

	for _, item := range inputs {
		key := strings.TrimSpace(item.Key)
		if err := ValidateEnvVarKey(key); err != nil {
			return nil, err
		}
		if _, dup := seen[key]; dup {
			return nil, ErrDuplicateEnvVarKey
		}
		seen[key] = struct{}{}

		if len(item.Value) > MaxEnvVarValueBytes {
			return nil, ErrEnvVarValueTooLarge
		}
		cleaned = append(cleaned, EnvVarInput{
			Key:   key,
			Value: item.Value,
		})
	}
	return cleaned, nil
}
