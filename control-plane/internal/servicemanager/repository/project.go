package repository

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgerrcode"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/skxm03/kr0n-backend/control-plane/internal/servicemanager/domain"
)

// UpdateProjectMutation holds mutable fields for updating a Project row and bumping its revision.
type UpdateProjectMutation struct {
	OrganizationID    uuid.UUID
	ProjectID         uuid.UUID
	Name              string
	Description       string
	ProductionBranch  string
	RootDirectory     string
	ApplicationPreset string
	ExpectedRevision  int64
	UpdatedAt         time.Time
}

// ProjectRepository defines persistence queries for projects and their 1:1 build settings.
type ProjectRepository interface {
	CreateProject(ctx context.Context, p *domain.Project) (*domain.Project, error)
	GetProject(ctx context.Context, orgID, projectID uuid.UUID) (*domain.Project, error)
	ListProjects(ctx context.Context, orgID uuid.UUID, limit, offset int) ([]domain.Project, error)
	UpdateProject(ctx context.Context, mut UpdateProjectMutation) (*domain.Project, error)
	UpdateBuildSettings(ctx context.Context, orgID, projectID uuid.UUID, expectedRevision int64, bs domain.BuildSettings) (*domain.Project, error)
	DeleteProject(ctx context.Context, orgID, projectID uuid.UUID) error
}

// PostgresProjectRepository implements ProjectRepository using PostgreSQL.
type PostgresProjectRepository struct {
	pool *pgxpool.Pool
}

// NewPostgresProjectRepository creates a PostgresProjectRepository backed by pgxpool.
func NewPostgresProjectRepository(pool *pgxpool.Pool) *PostgresProjectRepository {
	return &PostgresProjectRepository{pool: pool}
}

// CreateProject inserts a new row into `projects` (revision = 1) and its 1:1 row into `project_build_settings` atomically.
func (r *PostgresProjectRepository) CreateProject(ctx context.Context, p *domain.Project) (*domain.Project, error) {
	tx, err := r.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback(ctx)

	_, err = tx.Exec(ctx, `
		INSERT INTO projects (
			id, organization_id, name, slug, description,
			github_installation_id, repo_id, repo_owner, repo_name,
			production_branch, root_directory, application_preset,
			revision, created_by_user_id, created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5,
			$6, $7, $8, $9,
			$10, $11, $12,
			$13, $14, $15, $16
		);
	`,
		p.ID, p.OrganizationID, p.Name, p.Slug, p.Description,
		p.GitHubInstallationID, p.RepoID, p.RepoOwner, p.RepoName,
		p.ProductionBranch, p.RootDirectory, p.ApplicationPreset,
		p.Revision, p.CreatedByUserID, p.CreatedAt, p.UpdatedAt,
	)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) {
			if pgErr.Code == pgerrcode.UniqueViolation {
				return nil, domain.ErrProjectSlugConflict
			}
			if pgErr.Code == pgerrcode.ForeignKeyViolation {
				return nil, domain.ErrInstallationNotLinked
			}
		}
		return nil, fmt.Errorf("insert project: %w", err)
	}

	_, err = tx.Exec(ctx, `
		INSERT INTO project_build_settings (
			project_id,
			install_command, install_command_override,
			build_command, build_command_override,
			output_directory, output_directory_override,
			updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8);
	`,
		p.ID,
		p.BuildSettings.InstallCommand, p.BuildSettings.InstallCommandOverride,
		p.BuildSettings.BuildCommand, p.BuildSettings.BuildCommandOverride,
		p.BuildSettings.OutputDirectory, p.BuildSettings.OutputDirectoryOverride,
		p.BuildSettings.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("insert project build settings: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit create project: %w", err)
	}

	cp := *p
	cp.BuildSettings.ProjectID = p.ID
	return &cp, nil
}

const selectProjectWithBuildSettingsSQL = `
	SELECT
		p.id, p.organization_id, p.name, p.slug, p.description,
		p.github_installation_id, p.repo_id, p.repo_owner, p.repo_name,
		p.production_branch, p.root_directory, p.application_preset,
		p.revision, p.created_by_user_id, p.created_at, p.updated_at,
		bs.install_command, bs.install_command_override,
		bs.build_command, bs.build_command_override,
		bs.output_directory, bs.output_directory_override,
		bs.updated_at
	FROM projects p
	JOIN project_build_settings bs ON bs.project_id = p.id
`

func scanProjectRow(row pgx.Row) (*domain.Project, error) {
	var p domain.Project
	err := row.Scan(
		&p.ID, &p.OrganizationID, &p.Name, &p.Slug, &p.Description,
		&p.GitHubInstallationID, &p.RepoID, &p.RepoOwner, &p.RepoName,
		&p.ProductionBranch, &p.RootDirectory, &p.ApplicationPreset,
		&p.Revision, &p.CreatedByUserID, &p.CreatedAt, &p.UpdatedAt,
		&p.BuildSettings.InstallCommand, &p.BuildSettings.InstallCommandOverride,
		&p.BuildSettings.BuildCommand, &p.BuildSettings.BuildCommandOverride,
		&p.BuildSettings.OutputDirectory, &p.BuildSettings.OutputDirectoryOverride,
		&p.BuildSettings.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	p.BuildSettings.ProjectID = p.ID
	return &p, nil
}

// GetProject retrieves a project and its 1:1 build settings by orgID and projectID.
func (r *PostgresProjectRepository) GetProject(ctx context.Context, orgID, projectID uuid.UUID) (*domain.Project, error) {
	row := r.pool.QueryRow(ctx, selectProjectWithBuildSettingsSQL+`
		WHERE p.organization_id = $1 AND p.id = $2;
	`, orgID, projectID)

	p, err := scanProjectRow(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domain.ErrProjectNotFound
		}
		return nil, fmt.Errorf("get project: %w", err)
	}
	return p, nil
}

// ListProjects lists projects and their 1:1 build settings for orgID ordered newest-first.
func (r *PostgresProjectRepository) ListProjects(ctx context.Context, orgID uuid.UUID, limit, offset int) ([]domain.Project, error) {
	rows, err := r.pool.Query(ctx, selectProjectWithBuildSettingsSQL+`
		WHERE p.organization_id = $1
		ORDER BY p.created_at DESC
		LIMIT $2 OFFSET $3;
	`, orgID, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("list projects: %w", err)
	}
	defer rows.Close()

	var out []domain.Project
	for rows.Next() {
		p, err := scanProjectRow(rows)
		if err != nil {
			return nil, fmt.Errorf("scan project row: %w", err)
		}
		out = append(out, *p)
	}
	return out, rows.Err()
}

// UpdateProject updates a project's metadata, root directory, branch, or preset, and atomically increments revision.
func (r *PostgresProjectRepository) UpdateProject(ctx context.Context, mut UpdateProjectMutation) (*domain.Project, error) {
	tx, err := r.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback(ctx)

	var currentRev int64
	err = tx.QueryRow(ctx, `
		SELECT revision
		FROM projects
		WHERE organization_id = $1 AND id = $2
		FOR UPDATE;
	`, mut.OrganizationID, mut.ProjectID).Scan(&currentRev)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domain.ErrProjectNotFound
		}
		return nil, fmt.Errorf("lock project for update: %w", err)
	}

	if mut.ExpectedRevision > 0 && currentRev != mut.ExpectedRevision {
		return nil, domain.ErrRevisionConflict
	}

	_, err = tx.Exec(ctx, `
		UPDATE projects
		SET name = $1,
		    description = $2,
		    production_branch = $3,
		    root_directory = $4,
		    application_preset = $5,
		    revision = revision + 1,
		    updated_at = $6
		WHERE organization_id = $7 AND id = $8;
	`,
		mut.Name, mut.Description, mut.ProductionBranch, mut.RootDirectory, mut.ApplicationPreset,
		mut.UpdatedAt, mut.OrganizationID, mut.ProjectID,
	)
	if err != nil {
		return nil, fmt.Errorf("update project: %w", err)
	}

	row := tx.QueryRow(ctx, selectProjectWithBuildSettingsSQL+`
		WHERE p.organization_id = $1 AND p.id = $2;
	`, mut.OrganizationID, mut.ProjectID)
	updated, err := scanProjectRow(row)
	if err != nil {
		return nil, fmt.Errorf("reload updated project: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit update project: %w", err)
	}
	return updated, nil
}

// UpdateBuildSettings updates the 1:1 `project_build_settings` row and atomically increments `projects.revision`.
func (r *PostgresProjectRepository) UpdateBuildSettings(
	ctx context.Context,
	orgID, projectID uuid.UUID,
	expectedRevision int64,
	bs domain.BuildSettings,
) (*domain.Project, error) {
	tx, err := r.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback(ctx)

	var currentRev int64
	err = tx.QueryRow(ctx, `
		SELECT revision
		FROM projects
		WHERE organization_id = $1 AND id = $2
		FOR UPDATE;
	`, orgID, projectID).Scan(&currentRev)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domain.ErrProjectNotFound
		}
		return nil, fmt.Errorf("lock project for build settings update: %w", err)
	}

	if expectedRevision > 0 && currentRev != expectedRevision {
		return nil, domain.ErrRevisionConflict
	}

	now := bs.UpdatedAt
	if now.IsZero() {
		now = time.Now().UTC()
	}

	_, err = tx.Exec(ctx, `
		UPDATE project_build_settings
		SET install_command = $1,
		    install_command_override = $2,
		    build_command = $3,
		    build_command_override = $4,
		    output_directory = $5,
		    output_directory_override = $6,
		    updated_at = $7
		WHERE project_id = $8;
	`,
		bs.InstallCommand, bs.InstallCommandOverride,
		bs.BuildCommand, bs.BuildCommandOverride,
		bs.OutputDirectory, bs.OutputDirectoryOverride,
		now, projectID,
	)
	if err != nil {
		return nil, fmt.Errorf("update project build settings: %w", err)
	}

	_, err = tx.Exec(ctx, `
		UPDATE projects
		SET revision = revision + 1,
		    updated_at = $1
		WHERE organization_id = $2 AND id = $3;
	`, now, orgID, projectID)
	if err != nil {
		return nil, fmt.Errorf("increment project revision: %w", err)
	}

	row := tx.QueryRow(ctx, selectProjectWithBuildSettingsSQL+`
		WHERE p.organization_id = $1 AND p.id = $2;
	`, orgID, projectID)
	updated, err := scanProjectRow(row)
	if err != nil {
		return nil, fmt.Errorf("reload project after build settings update: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit update build settings: %w", err)
	}
	return updated, nil
}

// DeleteProject deletes a project from `projects` (cascading to `project_build_settings`).
func (r *PostgresProjectRepository) DeleteProject(ctx context.Context, orgID, projectID uuid.UUID) error {
	tag, err := r.pool.Exec(ctx, `
		DELETE FROM projects
		WHERE organization_id = $1 AND id = $2;
	`, orgID, projectID)
	if err != nil {
		return fmt.Errorf("delete project: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return domain.ErrProjectNotFound
	}
	return nil
}
