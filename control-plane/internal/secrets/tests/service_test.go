package tests

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	authv1 "github.com/skxm03/kr0n-backend/control-plane/gen/auth/v1"
	secretsv1 "github.com/skxm03/kr0n-backend/control-plane/gen/secrets/v1"
	"github.com/skxm03/kr0n-backend/control-plane/internal/secrets/crypto"
	"github.com/skxm03/kr0n-backend/control-plane/internal/secrets/domain"
	"github.com/skxm03/kr0n-backend/control-plane/internal/secrets/handlers"
	"github.com/skxm03/kr0n-backend/control-plane/internal/secrets/resolver"
	"github.com/skxm03/kr0n-backend/control-plane/internal/secrets/service"
	pkgAudit "github.com/skxm03/kr0n-backend/control-plane/pkg/audit"
)

// memorySecretsRepo is a pure in-memory persistence adapter with zero cryptographic knowledge.
type memorySecretsRepo struct {
	mu       sync.Mutex
	roles    map[uuid.UUID]string
	perms    map[string][]string
	projects map[uuid.UUID]uuid.UUID // projectID -> orgID
	keys     map[uuid.UUID]domain.ProjectKey
	envVars  map[uuid.UUID]map[string]map[string]domain.ProjectEnvVar // projectID -> env -> key -> row
}

func newMemorySecretsRepo() *memorySecretsRepo {
	return &memorySecretsRepo{
		roles: make(map[uuid.UUID]string),
		perms: map[string][]string{
			"owner":  {"project:create", "project:read", "project:update", "project:delete"},
			"member": {"project:read"},
		},
		projects: make(map[uuid.UUID]uuid.UUID),
		keys:     make(map[uuid.UUID]domain.ProjectKey),
		envVars:  make(map[uuid.UUID]map[string]map[string]domain.ProjectEnvVar),
	}
}

func (m *memorySecretsRepo) CheckPermission(_ context.Context, p domain.Principal, _ uuid.UUID, permission string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	role, ok := m.roles[p.UserID]
	if !ok {
		return false, nil
	}
	for _, perm := range m.perms[role] {
		if perm == permission {
			return true, nil
		}
	}
	return false, nil
}

func (m *memorySecretsRepo) VerifyProject(_ context.Context, orgID, projectID uuid.UUID) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	ownerOrg, ok := m.projects[projectID]
	return ok && ownerOrg == orgID, nil
}

func (m *memorySecretsRepo) ProjectExists(_ context.Context, projectID uuid.UUID) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.projects[projectID]
	return ok, nil
}

func (m *memorySecretsRepo) GetProjectKey(_ context.Context, projectID uuid.UUID) (*domain.ProjectKey, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	pk, ok := m.keys[projectID]
	if !ok {
		return nil, domain.ErrProjectKeyNotFound
	}
	cp := pk
	return &cp, nil
}

func (m *memorySecretsRepo) GetOrCreateProjectKey(_ context.Context, candidate domain.ProjectKey) (*domain.ProjectKey, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	pk, ok := m.keys[candidate.ProjectID]
	if !ok {
		candidate.CreatedAt = time.Now().UTC()
		candidate.UpdatedAt = candidate.CreatedAt
		m.keys[candidate.ProjectID] = candidate
		cp := candidate
		return &cp, nil
	}
	cp := pk
	return &cp, nil
}

func (m *memorySecretsRepo) UpsertEncryptedEnvVars(
	_ context.Context,
	projectID uuid.UUID,
	environment string,
	vars []domain.ProjectEnvVar,
) ([]domain.EnvVarMetadata, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.envVars[projectID] == nil {
		m.envVars[projectID] = make(map[string]map[string]domain.ProjectEnvVar)
	}
	if m.envVars[projectID][environment] == nil {
		m.envVars[projectID][environment] = make(map[string]domain.ProjectEnvVar)
	}

	out := make([]domain.EnvVarMetadata, 0, len(vars))
	for _, v := range vars {
		m.envVars[projectID][environment][v.Key] = v
		out = append(out, domain.EnvVarMetadata{
			ID:          v.ID,
			ProjectID:   projectID,
			Environment: environment,
			Key:         v.Key,
			MaskedValue: domain.MaskedSecretPlaceholder,
			HasValue:    true,
			DEKVersion:  v.DEKVersion,
			CreatedAt:   v.CreatedAt,
			UpdatedAt:   v.UpdatedAt,
		})
	}
	return out, nil
}

func (m *memorySecretsRepo) ListEnvVars(_ context.Context, orgID, projectID uuid.UUID, environment string) ([]domain.EnvVarMetadata, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	ownerOrg, ok := m.projects[projectID]
	if !ok || ownerOrg != orgID {
		return nil, domain.ErrProjectNotFound
	}
	var out []domain.EnvVarMetadata
	for _, row := range m.envVars[projectID][environment] {
		out = append(out, domain.EnvVarMetadata{
			ID:          row.ID,
			ProjectID:   projectID,
			Environment: environment,
			Key:         row.Key,
			MaskedValue: domain.MaskedSecretPlaceholder,
			HasValue:    true,
			DEKVersion:  row.DEKVersion,
			CreatedAt:   row.CreatedAt,
			UpdatedAt:   row.UpdatedAt,
		})
	}
	return out, nil
}

func (m *memorySecretsRepo) GetEncryptedEnvVars(_ context.Context, projectID uuid.UUID, environment string) ([]domain.ProjectEnvVar, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []domain.ProjectEnvVar
	for _, row := range m.envVars[projectID][environment] {
		out = append(out, row)
	}
	return out, nil
}

func (m *memorySecretsRepo) DeleteEnvVar(_ context.Context, orgID, projectID uuid.UUID, environment, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	ownerOrg, ok := m.projects[projectID]
	if !ok || ownerOrg != orgID {
		return domain.ErrProjectNotFound
	}
	envMap := m.envVars[projectID][environment]
	if _, exists := envMap[key]; !exists {
		return domain.ErrEnvVarNotFound
	}
	delete(envMap, key)
	return nil
}

func TestSecretsServiceAndHandlers_LifecycleAndAADTampering(t *testing.T) {
	ctx := context.Background()
	orgID := uuid.New()
	projID := uuid.New()
	ownerID := uuid.New()
	memberID := uuid.New()
	outsiderID := uuid.New()

	repo := newMemorySecretsRepo()
	repo.roles[ownerID] = "owner"
	repo.roles[memberID] = "member"
	repo.projects[projID] = orgID

	rawKEK, err := crypto.GenerateRandomKey()
	if err != nil {
		t.Fatalf("GenerateRandomKey: %v", err)
	}
	km, err := crypto.NewKeyManager(rawKEK, 1)
	if err != nil {
		t.Fatalf("NewKeyManager: %v", err)
	}

	cipher := crypto.NewEnvelopeCipher(km)
	svc := service.NewSecretsService(
		repo,
		cipher,
		service.WithAuthorizer(repo),
		service.WithProjectVerifier(repo),
	)
	auditEmitter := pkgAudit.NewMemoryEmitter("secrets")
	srv := handlers.NewServer(svc, handlers.WithAuditEmitter(auditEmitter))

	ownerCaller := &authv1.CallerPrincipal{UserId: ownerID.String(), Kind: "session"}
	memberCaller := &authv1.CallerPrincipal{UserId: memberID.String(), Kind: "session"}
	outsiderCaller := &authv1.CallerPrincipal{UserId: outsiderID.String(), Kind: "session"}

	// 1. Upsert secrets via public SecretsService
	upsertResp, err := srv.UpsertProjectEnvVars(ctx, &secretsv1.UpsertProjectEnvVarsRequest{
		Caller:      ownerCaller,
		OrgId:       orgID.String(),
		ProjectId:   projID.String(),
		Environment: "production",
		Variables: []*secretsv1.EnvVarInput{
			{Key: "DATABASE_URL", Value: "postgres://prod:secret@db:5432/billing"},
			{Key: "EMPTY_VAR", Value: ""},
		},
	})
	if err != nil || len(upsertResp.GetVariables()) != 2 {
		t.Fatalf("UpsertProjectEnvVars: err=%v count=%d", err, len(upsertResp.GetVariables()))
	}
	for _, v := range upsertResp.GetVariables() {
		if v.GetMaskedValue() != "••••••••" || !v.GetHasValue() || v.GetDekVersion() != 1 {
			t.Fatalf("expected masked metadata, got %+v", v)
		}
	}

	// 2. Member can list masked metadata; cannot upsert or delete
	listResp, err := srv.ListProjectEnvVars(ctx, &secretsv1.ListProjectEnvVarsRequest{
		Caller:      memberCaller,
		OrgId:       orgID.String(),
		ProjectId:   projID.String(),
		Environment: "production",
	})
	if err != nil || len(listResp.GetVariables()) != 2 {
		t.Fatalf("ListProjectEnvVars for member: err=%v count=%d", err, len(listResp.GetVariables()))
	}
	if _, err := srv.DeleteProjectEnvVar(ctx, &secretsv1.DeleteProjectEnvVarRequest{
		Caller:    memberCaller,
		OrgId:     orgID.String(),
		ProjectId: projID.String(),
		Key:       "DATABASE_URL",
	}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("expected PermissionDenied for member delete, got %v", err)
	}
	if _, err := srv.ListProjectEnvVars(ctx, &secretsv1.ListProjectEnvVarsRequest{
		Caller:    outsiderCaller,
		OrgId:     orgID.String(),
		ProjectId: projID.String(),
	}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("expected PermissionDenied for outsider list, got %v", err)
	}

	// 3. Internal SecretResolver & SecretsInternalServiceServer decrypt plaintext accurately
	var secResolver resolver.SecretResolver = svc
	resolved, err := secResolver.ResolveProjectSecrets(ctx, projID, "production")
	if err != nil {
		t.Fatalf("ResolveProjectSecrets: %v", err)
	}
	if resolved["DATABASE_URL"] != "postgres://prod:secret@db:5432/billing" || resolved["EMPTY_VAR"] != "" {
		t.Fatalf("unexpected resolved secrets: %+v", resolved)
	}

	internalResp, err := srv.ResolveProjectSecrets(ctx, &secretsv1.ResolveProjectSecretsRequest{
		ProjectId:   projID.String(),
		Environment: "production",
	})
	if err != nil || internalResp.GetSecrets()["DATABASE_URL"] != "postgres://prod:secret@db:5432/billing" {
		t.Fatalf("internal gRPC ResolveProjectSecrets failed: err=%v resp=%+v", err, internalResp)
	}

	// 4. Delete variable and verify subsequent delete returns NotFound
	if _, err := srv.DeleteProjectEnvVar(ctx, &secretsv1.DeleteProjectEnvVarRequest{
		Caller:      ownerCaller,
		OrgId:       orgID.String(),
		ProjectId:   projID.String(),
		Environment: "production",
		Key:         "EMPTY_VAR",
	}); err != nil {
		t.Fatalf("DeleteProjectEnvVar: %v", err)
	}
	if _, err := srv.DeleteProjectEnvVar(ctx, &secretsv1.DeleteProjectEnvVarRequest{
		Caller:      ownerCaller,
		OrgId:       orgID.String(),
		ProjectId:   projID.String(),
		Environment: "production",
		Key:         "EMPTY_VAR",
	}); status.Code(err) != codes.NotFound {
		t.Fatalf("expected NotFound on second delete, got %v", err)
	}

	// 5. Tamper with stored key name in repository and verify AAD prevents decryption
	repo.mu.Lock()
	row := repo.envVars[projID]["production"]["DATABASE_URL"]
	row.Key = "TAMPERED_KEY"
	repo.envVars[projID]["production"]["TAMPERED_KEY"] = row
	delete(repo.envVars[projID]["production"], "DATABASE_URL")
	repo.mu.Unlock()

	if _, err := secResolver.ResolveProjectSecrets(ctx, projID, "production"); !errors.Is(err, crypto.ErrDecryptionFailed) {
		t.Fatalf("expected ErrDecryptionFailed on tampered key AAD mismatch, got %v", err)
	}

	// 6. Verify audit events come from service "secrets" and contain keys only, never secret values
	for _, ev := range auditEmitter.Events() {
		if ev.Service != "secrets" {
			t.Fatalf("expected audit service 'secrets', got %q", ev.Service)
		}
		for k, v := range ev.Metadata {
			if s, ok := v.(string); ok && s == "postgres://prod:secret@db:5432/billing" {
				t.Fatalf("audit event %s leaked plaintext secret in metadata[%s]", ev.Action, k)
			}
		}
	}
}
