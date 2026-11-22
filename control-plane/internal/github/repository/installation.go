package repository

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/skxm03/kr0n-backend/control-plane/internal/github/domain"
)

// InstallationRepository defines data access methods for organization GitHub App installations.
type InstallationRepository interface {
	UpsertGitHubInstallation(ctx context.Context, inst *domain.GitHubInstallation) (*domain.GitHubInstallation, error)
	ListGitHubInstallations(ctx context.Context, orgID uuid.UUID) ([]domain.GitHubInstallation, error)
	DeleteGitHubInstallation(ctx context.Context, orgID uuid.UUID, installationID int64) error
	UpdateGitHubInstallationStatus(ctx context.Context, installationID int64, status string) error
	GetGitHubInstallationByInstallationID(ctx context.Context, installationID int64) (*domain.GitHubInstallation, error)
}

// PostgresInstallationRepository implements InstallationRepository on PostgreSQL.
type PostgresInstallationRepository struct {
	pool *pgxpool.Pool
}

// NewPostgresInstallationRepository creates a new PostgresInstallationRepository.
func NewPostgresInstallationRepository(pool *pgxpool.Pool) *PostgresInstallationRepository {
	return &PostgresInstallationRepository{pool: pool}
}

// UpsertGitHubInstallation inserts or updates a GitHub App installation for an organization.
func (r *PostgresInstallationRepository) UpsertGitHubInstallation(ctx context.Context, inst *domain.GitHubInstallation) (*domain.GitHubInstallation, error) {
	if inst == nil {
		return nil, domain.ErrInvalidInstallation
	}

	var out domain.GitHubInstallation
	var createdBy *uuid.UUID

	err := r.pool.QueryRow(ctx, `
		INSERT INTO github_installations (
			id, organization_id, installation_id, account_login, account_type,
			repository_selection, status, created_by_user_id, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		ON CONFLICT (installation_id) DO UPDATE
		SET account_login = EXCLUDED.account_login,
		    account_type = EXCLUDED.account_type,
		    repository_selection = EXCLUDED.repository_selection,
		    status = EXCLUDED.status,
		    updated_at = EXCLUDED.updated_at
		WHERE github_installations.organization_id = EXCLUDED.organization_id
		RETURNING id, organization_id, installation_id, account_login, account_type,
		          repository_selection, status, created_by_user_id, created_at, updated_at;
	`, inst.ID, inst.OrganizationID, inst.InstallationID, inst.AccountLogin, inst.AccountType,
		inst.RepositorySelection, inst.Status, inst.CreatedByUserID, inst.CreatedAt, inst.UpdatedAt).Scan(
		&out.ID, &out.OrganizationID, &out.InstallationID, &out.AccountLogin, &out.AccountType,
		&out.RepositorySelection, &out.Status, &createdBy, &out.CreatedAt, &out.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domain.ErrInstallationAlreadyLinked
		}
		return nil, fmt.Errorf("upsert github installation: %w", err)
	}
	if createdBy != nil {
		out.CreatedByUserID = *createdBy
	}
	return &out, nil
}

// ListGitHubInstallations returns all GitHub installations bound to orgID.
func (r *PostgresInstallationRepository) ListGitHubInstallations(ctx context.Context, orgID uuid.UUID) ([]domain.GitHubInstallation, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT id, organization_id, installation_id, account_login, account_type,
		       repository_selection, status, created_by_user_id, created_at, updated_at
		FROM github_installations
		WHERE organization_id = $1
		ORDER BY created_at DESC;
	`, orgID)
	if err != nil {
		return nil, fmt.Errorf("list github installations: %w", err)
	}
	defer rows.Close()

	var out []domain.GitHubInstallation
	for rows.Next() {
		var item domain.GitHubInstallation
		var createdBy *uuid.UUID
		if err := rows.Scan(
			&item.ID, &item.OrganizationID, &item.InstallationID, &item.AccountLogin, &item.AccountType,
			&item.RepositorySelection, &item.Status, &createdBy, &item.CreatedAt, &item.UpdatedAt,
		); err != nil {
			return nil, err
		}
		if createdBy != nil {
			item.CreatedByUserID = *createdBy
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

// DeleteGitHubInstallation removes a GitHub installation record from orgID.
func (r *PostgresInstallationRepository) DeleteGitHubInstallation(ctx context.Context, orgID uuid.UUID, installationID int64) error {
	tag, err := r.pool.Exec(ctx, `
		DELETE FROM github_installations
		WHERE organization_id = $1 AND installation_id = $2;
	`, orgID, installationID)
	if err != nil {
		return fmt.Errorf("delete github installation: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return domain.ErrInstallationNotFound
	}
	return nil
}

// UpdateGitHubInstallationStatus updates the lifecycle status ('active', 'suspended', 'deleted', 'uninstalled')
// of a GitHub App installation by its GitHub installation_id.
func (r *PostgresInstallationRepository) UpdateGitHubInstallationStatus(ctx context.Context, installationID int64, status string) error {
	tag, err := r.pool.Exec(ctx, `
		UPDATE github_installations
		SET status = $1, updated_at = now()
		WHERE installation_id = $2;
	`, status, installationID)
	if err != nil {
		return fmt.Errorf("update github installation status: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return domain.ErrInstallationNotFound
	}
	return nil
}

// GetGitHubInstallationByInstallationID looks up a GitHub installation record by its GitHub installation_id.
func (r *PostgresInstallationRepository) GetGitHubInstallationByInstallationID(ctx context.Context, installationID int64) (*domain.GitHubInstallation, error) {
	var out domain.GitHubInstallation
	var createdBy *uuid.UUID
	err := r.pool.QueryRow(ctx, `
		SELECT id, organization_id, installation_id, account_login, account_type,
		       repository_selection, status, created_by_user_id, created_at, updated_at
		FROM github_installations
		WHERE installation_id = $1;
	`, installationID).Scan(
		&out.ID, &out.OrganizationID, &out.InstallationID, &out.AccountLogin, &out.AccountType,
		&out.RepositorySelection, &out.Status, &createdBy, &out.CreatedAt, &out.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domain.ErrInstallationNotFound
		}
		return nil, fmt.Errorf("get github installation by id: %w", err)
	}
	if createdBy != nil {
		out.CreatedByUserID = *createdBy
	}
	return &out, nil
}
