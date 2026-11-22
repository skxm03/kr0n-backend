package service

import (
	"context"
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

// SecretsService orchestrates RBAC authorization, validation, and envelope encryption for Project Secrets.
type SecretsService struct {
	repo            repository.SecretsRepository
	keyManager      *crypto.KeyManager
	authorizer      Authorizer
	projectVerifier ProjectVerifier
}

// NewSecretsService creates a new SecretsService with its isolated Master KEK KeyManager and options.
func NewSecretsService(repo repository.SecretsRepository, keyManager *crypto.KeyManager, opts ...Option) *SecretsService {
	s := &SecretsService{
		repo:       repo,
		keyManager: keyManager,
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

// UpsertEnvVars authorizes caller with `project:update`, validates the environment name and variable batch,
// verifies project ownership via ProjectVerifier, and atomically encrypts and upserts the batch into `project_env_vars`.
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
	if s.keyManager == nil {
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
	return s.repo.UpsertEnvVars(ctx, orgID, projectID, env, cleaned, s.keyManager)
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
	if s.keyManager == nil {
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
	return s.repo.ResolvePlaintextSecrets(ctx, projectID, env, s.keyManager)
}
