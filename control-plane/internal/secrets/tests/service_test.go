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

func (m *memorySecretsRepo) RolePermissions(_ context.Context, userID, _ uuid.UUID) (string, []string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	role, ok := m.roles[userID]
	if !ok {
		return "", nil, domain.ErrForbidden
	}
	return role, m.perms[role], nil
}

func (m *memorySecretsRepo) GetOrCreateProjectDEK(_ context.Context, projectID uuid.UUID, km *crypto.KeyManager) ([]byte, int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.getOrCreateDEKLocked(projectID, km)
}

func (m *memorySecretsRepo) getOrCreateDEKLocked(projectID uuid.UUID, km *crypto.KeyManager) ([]byte, int, error) {
	if km == nil {
		return nil, 0, domain.ErrMasterKeyNotConfigured
	}
	pk, ok := m.keys[projectID]
	if !ok {
		dek, err := crypto.GenerateRandomKey()
		if err != nil {
			return nil, 0, err
		}
		enc, nonce, err := km.WrapDEK(projectID, dek)
		if err != nil {
			return nil, 0, err
		}
		pk = domain.ProjectKey{
			ProjectID:    projectID,
			EncryptedDEK: enc,
			Nonce:        nonce,
			DEKVersion:   1,
			KEKVersion:   km.KEKVersion(),
			CreatedAt:    time.Now().UTC(),
			UpdatedAt:    time.Now().UTC(),
		}
		m.keys[projectID] = pk
	}
	dek, err := km.UnwrapDEK(projectID, pk.EncryptedDEK, pk.Nonce)
	if err != nil {
		return nil, 0, err
	}
	return dek, pk.DEKVersion, nil
}

func (m *memorySecretsRepo) UpsertEnvVars(_ context.Context, orgID, projectID uuid.UUID, environment string, inputs []domain.EnvVarInput, km *crypto.KeyManager) ([]domain.EnvVarMetadata, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	ownerOrg, ok := m.projects[projectID]
	if !ok || ownerOrg != orgID {
		return nil, domain.ErrProjectNotFound
	}
	dek, dekVer, err := m.getOrCreateDEKLocked(projectID, km)
	if err != nil {
		return nil, err
	}
	if m.envVars[projectID] == nil {
		m.envVars[projectID] = make(map[string]map[string]domain.ProjectEnvVar)
	}
	if m.envVars[projectID][environment] == nil {
		m.envVars[projectID][environment] = make(map[string]domain.ProjectEnvVar)
	}

	now := time.Now().UTC()
	out := make([]domain.EnvVarMetadata, 0, len(inputs))
	for _, in := range inputs {
		ct, nonce, err := crypto.EncryptSecret(dek, projectID, environment, in.Key, in.Value)
		if err != nil {
			return nil, err
		}
		row, exists := m.envVars[projectID][environment][in.Key]
		if !exists {
			row = domain.ProjectEnvVar{
				ID:          uuid.New(),
				ProjectID:   projectID,
				Environment: environment,
				Key:         in.Key,
				CreatedAt:   now,
			}
		}
		row.EncryptedValue = ct
		row.Nonce = nonce
		row.DEKVersion = dekVer
		row.UpdatedAt = now
		m.envVars[projectID][environment][in.Key] = row

		out = append(out, domain.EnvVarMetadata{
			ID:          row.ID,
			ProjectID:   projectID,
			Environment: environment,
			Key:         in.Key,
			MaskedValue: domain.MaskedSecretPlaceholder,
			HasValue:    true,
			DEKVersion:  dekVer,
			CreatedAt:   row.CreatedAt,
			UpdatedAt:   row.UpdatedAt,
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

func (m *memorySecretsRepo) ResolvePlaintextSecrets(_ context.Context, projectID uuid.UUID, environment string, km *crypto.KeyManager) (map[string]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.projects[projectID]; !ok {
		return nil, domain.ErrProjectNotFound
	}
	pk, ok := m.keys[projectID]
	if !ok {
		return map[string]string{}, nil
	}
	dek, err := km.UnwrapDEK(projectID, pk.EncryptedDEK, pk.Nonce)
	if err != nil {
		return nil, err
	}
	out := make(map[string]string)
	for _, row := range m.envVars[projectID][environment] {
		plain, err := crypto.DecryptSecret(dek, projectID, environment, row.Key, row.EncryptedValue, row.Nonce)
		if err != nil {
			return nil, err
		}
		out[row.Key] = plain
	}
	return out, nil
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

	svc := service.NewSecretsService(repo, km)
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
