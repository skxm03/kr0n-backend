package service

import (
	"bytes"
	"context"
	"errors"
	"strings"

	"github.com/google/uuid"

	"github.com/skxm03/kr0n-backend/control-plane/internal/secrets/crypto"
	"github.com/skxm03/kr0n-backend/control-plane/internal/secrets/domain"
	"github.com/skxm03/kr0n-backend/control-plane/internal/secrets/repository"
	"github.com/skxm03/kr0n-backend/control-plane/internal/secrets/resolver"
)

// Compile-time check that SecretsService satisfies resolver.SecretResolver.
var _ resolver.SecretResolver = (*SecretsService)(nil)

// Option configures a SecretsService instance.
type Option func(*SecretsService)

// WithAuthorizer configures an external Authorizer for RBAC evaluations.
func WithAuthorizer(a Authorizer) Option {
	return func(s *SecretsService) {
		s.authorizer = a
	}
}

// WithProjectVerifier configures an external ProjectVerifier for project checks.
func WithProjectVerifier(v ProjectVerifier) Option {
	return func(s *SecretsService) {
		s.projectVerifier = v
	}
}

// SecretsService orchestrates RBAC authorization, validation, cryptographic operations, and persistence for Project Secrets.
type SecretsService struct {
	repo            repository.SecretsRepository
	cipher          crypto.VaultCipher
	authorizer      Authorizer
	projectVerifier ProjectVerifier
}

// NewSecretsService creates a new SecretsService with its isolated VaultCipher and options.
func NewSecretsService(repo repository.SecretsRepository, cipher crypto.VaultCipher, opts ...Option) *SecretsService {
	s := &SecretsService{
		repo:   repo,
		cipher: cipher,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// Can checks whether caller principal p holds permission in orgID.
func (s *SecretsService) Can(ctx context.Context, p domain.Principal, orgID uuid.UUID, permission string) (bool, error) {
	if p.UserID == uuid.Nil || orgID == uuid.Nil || permission == "" {
		return false, nil
	}
	if p.Kind == "api_token" {
		if p.TokenOrgID == nil || *p.TokenOrgID != orgID || !hasPermission(p.TokenPermissions, permission) {
			return false, nil
		}
	}

	if s.authorizer != nil {
		return s.authorizer.CheckPermission(ctx, p, orgID, permission)
	}
	return false, nil
}

func (s *SecretsService) require(ctx context.Context, p domain.Principal, orgID uuid.UUID, permission string) error {
	allowed, err := s.Can(ctx, p, orgID, permission)
	if err != nil {
		return err
	}
	if !allowed {
		return domain.ErrForbidden
	}
	return nil
}

func hasPermission(perms []string, permission string) bool {
	for _, perm := range perms {
		if perm == permission {
			return true
		}
	}
	return false
}

func (s *SecretsService) getOrGenerateDEK(ctx context.Context, projectID uuid.UUID) ([]byte, int, error) {
	if s.cipher == nil {
		return nil, 0, domain.ErrMasterKeyNotConfigured
	}

	existingKey, err := s.repo.GetProjectKey(ctx, projectID)
	if err == nil && existingKey != nil {
		dek, err := s.cipher.UnwrapProjectKey(existingKey)
		if err != nil {
			return nil, 0, err
		}
		return dek, existingKey.DEKVersion, nil
	}
	if err != nil && !errors.Is(err, domain.ErrProjectKeyNotFound) {
		return nil, 0, err
	}

	candidateKey, rawDEK, err := s.cipher.GenerateProjectKey(projectID)
	if err != nil {
		return nil, 0, err
	}

	persistedKey, err := s.repo.GetOrCreateProjectKey(ctx, *candidateKey)
	if err != nil {
		return nil, 0, err
	}

	// If another concurrent request won the insert race, unwrap the winner's key
	if !bytes.Equal(persistedKey.EncryptedDEK, candidateKey.EncryptedDEK) {
		dek, err := s.cipher.UnwrapProjectKey(persistedKey)
		if err != nil {
			return nil, 0, err
		}
		return dek, persistedKey.DEKVersion, nil
	}

	return rawDEK, persistedKey.DEKVersion, nil
}

// UpsertEnvVars authorizes caller with `project:update`, validates the environment name and variable batch,
// verifies project ownership via ProjectVerifier, encrypts secrets via VaultCipher, and upserts them into `project_env_vars`.
// Returns only masked metadata; raw secret values are never returned.
func (s *SecretsService) UpsertEnvVars(
	ctx context.Context,
	p domain.Principal,
	orgID, projectID uuid.UUID,
	rawEnvironment string,
	inputs []domain.EnvVarInput,
) ([]domain.EnvVarMetadata, error) {
	if err := s.require(ctx, p, orgID, "project:update"); err != nil {
		return nil, err
	}
	if s.cipher == nil {
		return nil, domain.ErrMasterKeyNotConfigured
	}
	env, err := domain.NormalizeEnvironment(rawEnvironment)
	if err != nil {
		return nil, err
	}
	cleaned, err := domain.ValidateEnvVarBatch(inputs)
	if err != nil {
		return nil, err
	}
	if s.projectVerifier != nil {
		ok, err := s.projectVerifier.VerifyProject(ctx, orgID, projectID)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, domain.ErrProjectNotFound
		}
	}

	dek, dekVer, err := s.getOrGenerateDEK(ctx, projectID)
	if err != nil {
		return nil, err
	}

	encryptedVars, err := s.cipher.EncryptEnvVars(projectID, env, dek, dekVer, cleaned)
	if err != nil {
		return nil, err
	}

	return s.repo.UpsertEncryptedEnvVars(ctx, projectID, env, encryptedVars)
}

// ListEnvVars authorizes caller with `project:read`, validates the environment name,
// verifies project ownership via ProjectVerifier, and returns masked metadata (`••••••••`) for all stored
// environment variables without decrypting ciphertext.
func (s *SecretsService) ListEnvVars(
	ctx context.Context,
	p domain.Principal,
	orgID, projectID uuid.UUID,
	rawEnvironment string,
) ([]domain.EnvVarMetadata, error) {
	if err := s.require(ctx, p, orgID, "project:read"); err != nil {
		return nil, err
	}
	env, err := domain.NormalizeEnvironment(rawEnvironment)
	if err != nil {
		return nil, err
	}
	if s.projectVerifier != nil {
		ok, err := s.projectVerifier.VerifyProject(ctx, orgID, projectID)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, domain.ErrProjectNotFound
		}
	}
	return s.repo.ListEnvVars(ctx, orgID, projectID, env)
}

// DeleteEnvVar authorizes caller with `project:update`, validates the environment name and variable key,
// verifies project ownership via ProjectVerifier, and permanently deletes the variable from `project_env_vars`.
func (s *SecretsService) DeleteEnvVar(
	ctx context.Context,
	p domain.Principal,
	orgID, projectID uuid.UUID,
	rawEnvironment, rawKey string,
) error {
	if err := s.require(ctx, p, orgID, "project:update"); err != nil {
		return err
	}
	env, err := domain.NormalizeEnvironment(rawEnvironment)
	if err != nil {
		return err
	}
	key := strings.TrimSpace(rawKey)
	if key == "" {
		return domain.ErrInvalidEnvVarKey
	}
	if s.projectVerifier != nil {
		ok, err := s.projectVerifier.VerifyProject(ctx, orgID, projectID)
		if err != nil {
			return err
		}
		if !ok {
			return domain.ErrProjectNotFound
		}
	}
	return s.repo.DeleteEnvVar(ctx, orgID, projectID, env, key)
}

// ResolveProjectSecrets satisfies resolver.SecretResolver for the trusted internal build/deployment path.
func (s *SecretsService) ResolveProjectSecrets(
	ctx context.Context,
	projectID uuid.UUID,
	rawEnvironment string,
) (map[string]string, error) {
	if projectID == uuid.Nil {
		return nil, domain.ErrProjectNotFound
	}
	if s.cipher == nil {
		return nil, domain.ErrMasterKeyNotConfigured
	}
	env, err := domain.NormalizeEnvironment(rawEnvironment)
	if err != nil {
		return nil, err
	}
	if s.projectVerifier != nil {
		ok, err := s.projectVerifier.ProjectExists(ctx, projectID)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, domain.ErrProjectNotFound
		}
	}

	key, err := s.repo.GetProjectKey(ctx, projectID)
	if err != nil {
		if errors.Is(err, domain.ErrProjectKeyNotFound) {
			return map[string]string{}, nil
		}
		return nil, err
	}

	dek, err := s.cipher.UnwrapProjectKey(key)
	if err != nil {
		return nil, err
	}

	records, err := s.repo.GetEncryptedEnvVars(ctx, projectID, env)
	if err != nil {
		return nil, err
	}

	return s.cipher.DecryptEnvVars(projectID, env, dek, records)
}
