package tests

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/skxm03/kr0n-backend/control-plane/internal/auth/repository"
	"github.com/skxm03/kr0n-backend/control-plane/internal/auth/service"
	"github.com/skxm03/kr0n-backend/control-plane/internal/testdb"
)

func TestOrgPostgresRepository_APITokenMembershipDemotionAndRemoval(t *testing.T) {
	pool := testdb.Pool(t)
	repo := repository.NewPostgresOrgRepository(pool)
	svc := service.NewOrgService(repo)
	ctx := context.Background()

	ownerID := uuid.New()
	adminID := uuid.New()
	ownerEmail := "org_owner_" + ownerID.String() + "@kr0n.dev"
	adminEmail := "org_admin_" + adminID.String() + "@kr0n.dev"

	for _, u := range []struct {
		id    uuid.UUID
		email string
	}{{ownerID, ownerEmail}, {adminID, adminEmail}} {
		if _, err := pool.Exec(ctx, `
			INSERT INTO users (id, email, email_verified_at, display_name, status)
			VALUES ($1, $2, now(), 'Org Test', 'active')
		`, u.id, u.email); err != nil {
			t.Fatalf("insert user %s: %v", u.email, err)
		}
	}

	slug := "org-pg-" + uuid.NewString()[:8]
	orgObj, err := svc.CreateOrg(ctx, ownerID, "PG Org", slug)
	if err != nil {
		t.Fatalf("CreateOrg: %v", err)
	}
	ownerP := repository.Principal{UserID: ownerID, Kind: "session"}
	adminP := repository.Principal{UserID: adminID, Kind: "session"}

	if _, err := svc.AddMember(ctx, ownerP, orgObj.ID, adminEmail, "admin"); err != nil {
		t.Fatalf("AddMember: %v", err)
	}

	// Admin cannot invite an already-existing member
	if _, _, err := svc.CreateInvite(ctx, adminP, orgObj.ID, ownerEmail, "member"); !errors.Is(err, repository.ErrMemberAlreadyExists) {
		t.Fatalf("expected ErrMemberAlreadyExists when inviting existing member, got %v", err)
	}

	// Admin mints an API token with project:read, project:create, member:delete
	tok, rawSecret, err := svc.CreateAPIToken(ctx, adminP, orgObj.ID, "admin-ci", []string{"project:read", "project:create", "member:delete"}, 3600)
	if err != nil {
		t.Fatalf("CreateAPIToken: %v", err)
	}

	validated, err := svc.ValidateAPIToken(ctx, rawSecret)
	if err != nil || len(validated.Permissions) != 3 {
		t.Fatalf("ValidateAPIToken: err=%v perms=%v", err, validated)
	}

	// Demote admin -> member: token validation and Can must immediately lose member:delete
	if err := svc.UpdateMemberRole(ctx, ownerP, orgObj.ID, adminID, "member"); err != nil {
		t.Fatalf("UpdateMemberRole: %v", err)
	}
	validatedAfterDemote, err := svc.ValidateAPIToken(ctx, rawSecret)
	if err != nil {
		t.Fatalf("ValidateAPIToken after demote: %v", err)
	}
	for _, p := range validatedAfterDemote.Permissions {
		if p == "member:delete" {
			t.Fatalf("demoted member must not retain member:delete in validated token: %v", validatedAfterDemote.Permissions)
		}
	}
	staleP := repository.Principal{
		UserID:           tok.CreatedByUserID,
		Kind:             "api_token",
		TokenOrgID:       &orgObj.ID,
		TokenPermissions: []string{"project:read", "project:create", "member:delete"},
	}
	if ok, _ := svc.Can(ctx, staleP, orgObj.ID, "member:delete"); ok {
		t.Fatal("Can must deny member:delete after creator is demoted to member")
	}

	// Concurrent RemoveMember and ValidateAPIToken in PostgreSQL: once RemoveMember completes,
	// the token row is marked revoked_at IS NOT NULL and all subsequent validations fail.
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				_, err := svc.ValidateAPIToken(ctx, rawSecret)
				if err != nil && !errors.Is(err, repository.ErrInvalidAPIToken) {
					t.Errorf("unexpected error during concurrent ValidateAPIToken: %v", err)
					return
				}
			}
		}()
	}
	if err := svc.RemoveMember(ctx, ownerP, orgObj.ID, adminID); err != nil {
		t.Fatalf("RemoveMember: %v", err)
	}
	wg.Wait()

	if _, err := svc.ValidateAPIToken(ctx, rawSecret); !errors.Is(err, repository.ErrInvalidAPIToken) {
		t.Fatalf("expected ErrInvalidAPIToken after creator removal, got %v", err)
	}
	var revokedAt *time.Time
	if err := pool.QueryRow(ctx, `SELECT revoked_at FROM api_tokens WHERE id = $1`, tok.ID).Scan(&revokedAt); err != nil || revokedAt == nil {
		t.Fatalf("expected api_tokens.revoked_at to be set on RemoveMember, err=%v revokedAt=%v", err, revokedAt)
	}

	// Inactive creator user status is also rejected
	ownerTok, ownerSecret, err := svc.CreateAPIToken(ctx, ownerP, orgObj.ID, "owner-ci", []string{"org:read"}, 3600)
	if err != nil || ownerTok == nil {
		t.Fatalf("CreateAPIToken owner: %v", err)
	}
	if _, err := pool.Exec(ctx, `UPDATE users SET status = 'suspended' WHERE id = $1`, ownerID); err != nil {
		t.Fatalf("suspend owner: %v", err)
	}
	if _, err := svc.ValidateAPIToken(ctx, ownerSecret); !errors.Is(err, repository.ErrUserNotActive) {
		t.Fatalf("expected ErrUserNotActive for suspended token creator, got %v", err)
	}
}

func TestOrgPostgresRepository_GitHubInstallations(t *testing.T) {
	pool := testdb.Pool(t)
	repo := repository.NewPostgresOrgRepository(pool)
	ctx := context.Background()

	userID := uuid.New()
	if _, err := pool.Exec(ctx, `
		INSERT INTO users (id, email, email_verified_at, display_name, status)
		VALUES ($1, $2, now(), 'GH Owner', 'active')
	`, userID, "gh_owner_"+userID.String()+"@kr0n.dev"); err != nil {
		t.Fatalf("insert user: %v", err)
	}

	org1 := &repository.Organization{
		ID:        uuid.New(),
		Name:      "Org One",
		Slug:      "org-one-" + uuid.NewString()[:8],
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}
	org2 := &repository.Organization{
		ID:        uuid.New(),
		Name:      "Org Two",
		Slug:      "org-two-" + uuid.NewString()[:8],
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}
	if err := repo.CreateOrg(ctx, org1, userID); err != nil {
		t.Fatalf("CreateOrg org1: %v", err)
	}
	if err := repo.CreateOrg(ctx, org2, userID); err != nil {
		t.Fatalf("CreateOrg org2: %v", err)
	}

	inst := &repository.GitHubInstallation{
		ID:                  uuid.New(),
		OrganizationID:      org1.ID,
		InstallationID:      849204,
		AccountLogin:        "kr0n-org",
		AccountType:         "Organization",
		RepositorySelection: "all",
		Status:              "active",
		CreatedByUserID:     userID,
		CreatedAt:           time.Now().UTC(),
		UpdatedAt:           time.Now().UTC(),
	}

	saved, err := repo.UpsertGitHubInstallation(ctx, inst)
	if err != nil {
		t.Fatalf("UpsertGitHubInstallation: %v", err)
	}
	if saved.InstallationID != 849204 || saved.AccountLogin != "kr0n-org" {
		t.Fatalf("unexpected saved installation: %+v", saved)
	}

	// Re-upserting for the SAME org updates metadata idempotently
	inst.RepositorySelection = "selected"
	updated, err := repo.UpsertGitHubInstallation(ctx, inst)
	if err != nil {
		t.Fatalf("UpsertGitHubInstallation idempotent update: %v", err)
	}
	if updated.RepositorySelection != "selected" {
		t.Fatalf("expected updated RepositorySelection='selected', got %s", updated.RepositorySelection)
	}

	// Another org attempting to claim the same installation_id must fail with ErrInstallationAlreadyLinked
	hijack := *inst
	hijack.ID = uuid.New()
	hijack.OrganizationID = org2.ID
	if _, err := repo.UpsertGitHubInstallation(ctx, &hijack); !errors.Is(err, repository.ErrInstallationAlreadyLinked) {
		t.Fatalf("expected ErrInstallationAlreadyLinked when another org claims installation, got %v", err)
	}

	list, err := repo.ListGitHubInstallations(ctx, org1.ID)
	if err != nil || len(list) != 1 || list[0].InstallationID != 849204 {
		t.Fatalf("ListGitHubInstallations: err=%v list=%+v", err, list)
	}

	// Webhook lifecycle status updates: suspended -> active -> deleted
	for _, st := range []string{"suspended", "active", "deleted"} {
		if err := repo.UpdateGitHubInstallationStatus(ctx, 849204, st); err != nil {
			t.Fatalf("UpdateGitHubInstallationStatus(%s): %v", st, err)
		}
		fetched, err := repo.GetGitHubInstallationByInstallationID(ctx, 849204)
		if err != nil || fetched.Status != st || fetched.OrganizationID != org1.ID {
			t.Fatalf("GetGitHubInstallationByInstallationID after %s: err=%v fetched=%+v", st, err, fetched)
		}
	}

	if err := repo.DeleteGitHubInstallation(ctx, org2.ID, 849204); !errors.Is(err, repository.ErrInstallationNotFound) {
		t.Fatalf("expected ErrInstallationNotFound for wrong org delete, got %v", err)
	}

	if err := repo.DeleteGitHubInstallation(ctx, org1.ID, 849204); err != nil {
		t.Fatalf("DeleteGitHubInstallation: %v", err)
	}

	afterDelete, err := repo.ListGitHubInstallations(ctx, org1.ID)
	if err != nil || len(afterDelete) != 0 {
		t.Fatalf("expected empty list after delete, err=%v list=%+v", err, afterDelete)
	}
}

