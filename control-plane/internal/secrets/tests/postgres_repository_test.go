package tests

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	authv1 "github.com/skxm03/kr0n-backend/control-plane/gen/auth/v1"
	secretsv1 "github.com/skxm03/kr0n-backend/control-plane/gen/secrets/v1"
	"github.com/skxm03/kr0n-backend/control-plane/internal/secrets/crypto"
	"github.com/skxm03/kr0n-backend/control-plane/internal/secrets/domain"
	"github.com/skxm03/kr0n-backend/control-plane/internal/secrets/handlers"
	"github.com/skxm03/kr0n-backend/control-plane/internal/secrets/repository"
	"github.com/skxm03/kr0n-backend/control-plane/internal/secrets/resolver"
	"github.com/skxm03/kr0n-backend/control-plane/internal/secrets/service"
	"github.com/skxm03/kr0n-backend/control-plane/internal/testdb"
	pkgAudit "github.com/skxm03/kr0n-backend/control-plane/pkg/audit"
)

func TestSecrets_PostgresConcurrencyAndAADTampering(t *testing.T) {
	pool := testdb.Pool(t)
	ctx := context.Background()

	ownerID := uuid.New()
	memberID := uuid.New()
	outsiderID := uuid.New()

	for _, u := range []struct {
		id    uuid.UUID
		email string
	}{
		{ownerID, "sec_owner_" + ownerID.String() + "@kr0n.dev"},
		{memberID, "sec_member_" + memberID.String() + "@kr0n.dev"},
		{outsiderID, "sec_outsider_" + outsiderID.String() + "@kr0n.dev"},
	} {
		if _, err := pool.Exec(ctx, `
			INSERT INTO users (id, email, email_verified_at, display_name, status)
			VALUES ($1, $2, now(), 'Secret Test', 'active')
		`, u.id, u.email); err != nil {
			t.Fatalf("insert user: %v", err)
		}
	}

	orgID := uuid.New()
	if _, err := pool.Exec(ctx, `
		INSERT INTO organizations (id, name, slug) VALUES ($1, 'Secret Org', $2)
	`, orgID, "sec-org-"+uuid.NewString()[:8]); err != nil {
		t.Fatalf("insert org: %v", err)
	}
	for _, m := range []struct {
		uid  uuid.UUID
		role string
	}{
		{ownerID, "owner"},
		{memberID, "member"},
	} {
		if _, err := pool.Exec(ctx, `
			INSERT INTO organization_memberships (id, organization_id, user_id, role_id)
			VALUES ($1, $2, $3, $4)
		`, uuid.New(), orgID, m.uid, m.role); err != nil {
			t.Fatalf("insert membership: %v", err)
		}
	}

	instID := int64(92001)
	if _, err := pool.Exec(ctx, `
		INSERT INTO github_installations (
			id, organization_id, installation_id, account_login, account_type, repository_selection, status, created_by_user_id
		) VALUES ($1, $2, $3, 'acme-sec', 'Organization', 'all', 'active', $4)
	`, uuid.New(), orgID, instID, ownerID); err != nil {
		t.Fatalf("insert installation: %v", err)
	}

	projID := uuid.New()
	if _, err := pool.Exec(ctx, `
		INSERT INTO projects (
			id, organization_id, name, slug, description, github_installation_id,
			repo_owner, repo_name, production_branch, root_directory, application_preset, revision, created_by_user_id
		) VALUES ($1, $2, 'Payments API', 'payments-api', '', $3, 'acme-sec', 'payments', 'main', '/', 'auto', 1, $4)
	`, projID, orgID, instID, ownerID); err != nil {
		t.Fatalf("insert project: %v", err)
	}

	rawKEK, err := crypto.GenerateRandomKey()
	if err != nil {
		t.Fatalf("GenerateRandomKey: %v", err)
	}
	km, err := crypto.NewKeyManager(rawKEK, 1)
	if err != nil {
		t.Fatalf("NewKeyManager: %v", err)
	}
	cipher := crypto.NewEnvelopeCipher(km)

	repo := repository.NewPostgresSecretsRepository(pool)
	authorizer := service.NewLocalDBAuthorizer(pool)
	projectVerifier := service.NewLocalDBProjectVerifier(pool)
	svc := service.NewSecretsService(
		repo,
		cipher,
		service.WithAuthorizer(authorizer),
		service.WithProjectVerifier(projectVerifier),
	)
	auditEmitter := pkgAudit.NewMemoryEmitter("secrets")
	srv := handlers.NewServer(svc, handlers.WithAuditEmitter(auditEmitter))

	ownerCaller := &authv1.CallerPrincipal{UserId: ownerID.String(), Kind: "session"}
	memberCaller := &authv1.CallerPrincipal{UserId: memberID.String(), Kind: "session"}
	outsiderCaller := &authv1.CallerPrincipal{UserId: outsiderID.String(), Kind: "session"}

	// 1. Atomic DEK creation concurrency race test: 10 concurrent goroutines racing to create project key
	const workers = 10
	deks := make([][]byte, workers)
	errs := make([]error, workers)
	var wg sync.WaitGroup
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func(idx int) {
			defer wg.Done()
			candidate, _, gErr := cipher.GenerateProjectKey(projID)
			if gErr != nil {
				errs[idx] = gErr
				return
			}
			persisted, pErr := repo.GetOrCreateProjectKey(ctx, *candidate)
			if pErr != nil {
				errs[idx] = pErr
				return
			}
			dek, uErr := cipher.UnwrapProjectKey(persisted)
			if uErr == nil && persisted.DEKVersion != 1 {
				uErr = errors.New("expected dek_version 1")
			}
			deks[idx] = dek
			errs[idx] = uErr
		}(i)
	}
	wg.Wait()

	for i := 0; i < workers; i++ {
		if errs[i] != nil {
			t.Fatalf("worker %d GetOrCreateProjectKey failed: %v", i, errs[i])
		}
		if len(deks[i]) != 32 || !bytes.Equal(deks[0], deks[i]) {
			t.Fatalf("worker %d DEK mismatch: concurrent DEK creation race detected", i)
		}
	}

	// 2. UpsertProjectEnvVars in production & preview
	upsertResp, err := srv.UpsertProjectEnvVars(ctx, &secretsv1.UpsertProjectEnvVarsRequest{
		Caller:      ownerCaller,
		OrgId:       orgID.String(),
		ProjectId:   projID.String(),
		Environment: "production",
		Variables: []*secretsv1.EnvVarInput{
			{Key: "DATABASE_URL", Value: "postgres://prod:supersecret@db.internal:5432/payments"},
			{Key: "STRIPE_SECRET_KEY", Value: "sk_live_9988776655"},
			{Key: "OPTIONAL_WEBHOOK_URL", Value: ""},
		},
	})
	if err != nil || len(upsertResp.GetVariables()) != 3 {
		t.Fatalf("UpsertProjectEnvVars: err=%v count=%d", err, len(upsertResp.GetVariables()))
	}
	for _, v := range upsertResp.GetVariables() {
		if v.GetMaskedValue() != domain.MaskedSecretPlaceholder || !v.GetHasValue() || v.GetDekVersion() != 1 {
			t.Fatalf("expected masked write-only metadata, got %+v", v)
		}
	}

	// 3. ListProjectEnvVars allowed for member, denied for outsider
	if _, err := srv.ListProjectEnvVars(ctx, &secretsv1.ListProjectEnvVarsRequest{
		Caller:    outsiderCaller,
		OrgId:     orgID.String(),
		ProjectId: projID.String(),
	}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("expected PermissionDenied for outsider ListProjectEnvVars, got %v", err)
	}
	listEnvResp, err := srv.ListProjectEnvVars(ctx, &secretsv1.ListProjectEnvVarsRequest{
		Caller:      memberCaller,
		OrgId:       orgID.String(),
		ProjectId:   projID.String(),
		Environment: "production",
	})
	if err != nil || len(listEnvResp.GetVariables()) != 3 {
		t.Fatalf("ListProjectEnvVars member: err=%v count=%d", err, len(listEnvResp.GetVariables()))
	}

	// 4. Internal SecretResolver decrypts exact values
	var secretResolver resolver.SecretResolver = svc
	prodSecrets, err := secretResolver.ResolveProjectSecrets(ctx, projID, "production")
	if err != nil || prodSecrets["DATABASE_URL"] != "postgres://prod:supersecret@db.internal:5432/payments" {
		t.Fatalf("ResolveProjectSecrets production: err=%v map=%+v", err, prodSecrets)
	}

	// 5. DeleteProjectEnvVar removes variable and returns NotFound if deleted again
	if _, err := srv.DeleteProjectEnvVar(ctx, &secretsv1.DeleteProjectEnvVarRequest{
		Caller:      ownerCaller,
		OrgId:       orgID.String(),
		ProjectId:   projID.String(),
		Environment: "production",
		Key:         "OPTIONAL_WEBHOOK_URL",
	}); err != nil {
		t.Fatalf("DeleteProjectEnvVar: %v", err)
	}
	if _, err := srv.DeleteProjectEnvVar(ctx, &secretsv1.DeleteProjectEnvVarRequest{
		Caller:      ownerCaller,
		OrgId:       orgID.String(),
		ProjectId:   projID.String(),
		Environment: "production",
		Key:         "OPTIONAL_WEBHOOK_URL",
	}); status.Code(err) != codes.NotFound {
		t.Fatalf("expected NotFound when deleting non-existent env var, got %v", err)
	}

	// 6. Database AAD Tampering Defense
	if _, err := pool.Exec(ctx, `
		UPDATE project_env_vars
		SET key = 'HIJACKED_KEY'
		WHERE project_id = $1 AND environment = 'production' AND key = 'STRIPE_SECRET_KEY';
	`, projID); err != nil {
		t.Fatalf("tamper key in db: %v", err)
	}
	if _, err := secretResolver.ResolveProjectSecrets(ctx, projID, "production"); !errors.Is(err, crypto.ErrDecryptionFailed) {
		t.Fatalf("expected ErrDecryptionFailed after AAD key tampering in DB, got %v", err)
	}
}
