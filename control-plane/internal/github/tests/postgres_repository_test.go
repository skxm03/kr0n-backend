package tests

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/skxm03/kr0n-backend/control-plane/internal/github/domain"
	"github.com/skxm03/kr0n-backend/control-plane/internal/github/repository"
	"github.com/skxm03/kr0n-backend/control-plane/internal/testdb"
)

func TestPostgresInstallationRepository(t *testing.T) {
	pool := testdb.Pool(t)
	repo := repository.NewPostgresInstallationRepository(pool)
	ctx := context.Background()

	org1ID := uuid.New()
	org2ID := uuid.New()
	userID := uuid.New()

	inst := &domain.GitHubInstallation{
		ID:                  uuid.New(),
		OrganizationID:      org1ID,
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
	hijack.OrganizationID = org2ID
	if _, err := repo.UpsertGitHubInstallation(ctx, &hijack); !errors.Is(err, domain.ErrInstallationAlreadyLinked) {
		t.Fatalf("expected ErrInstallationAlreadyLinked when another org claims installation, got %v", err)
	}

	list, err := repo.ListGitHubInstallations(ctx, org1ID)
	if err != nil || len(list) != 1 || list[0].InstallationID != 849204 {
		t.Fatalf("ListGitHubInstallations: err=%v list=%+v", err, list)
	}

	// Webhook lifecycle status updates: suspended -> active -> deleted
	for _, st := range []string{"suspended", "active", "deleted"} {
		if err := repo.UpdateGitHubInstallationStatus(ctx, 849204, st); err != nil {
			t.Fatalf("UpdateGitHubInstallationStatus(%s): %v", st, err)
		}
		fetched, err := repo.GetGitHubInstallationByInstallationID(ctx, 849204)
		if err != nil || fetched.Status != st || fetched.OrganizationID != org1ID {
			t.Fatalf("GetGitHubInstallationByInstallationID after %s: err=%v fetched=%+v", st, err, fetched)
		}
	}

	if err := repo.DeleteGitHubInstallation(ctx, org2ID, 849204); !errors.Is(err, domain.ErrInstallationNotFound) {
		t.Fatalf("expected ErrInstallationNotFound for wrong org delete, got %v", err)
	}

	if err := repo.DeleteGitHubInstallation(ctx, org1ID, 849204); err != nil {
		t.Fatalf("DeleteGitHubInstallation: %v", err)
	}

	afterDelete, err := repo.ListGitHubInstallations(ctx, org1ID)
	if err != nil || len(afterDelete) != 0 {
		t.Fatalf("expected empty list after delete, err=%v list=%+v", err, afterDelete)
	}
}
