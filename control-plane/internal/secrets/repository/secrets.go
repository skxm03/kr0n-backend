package repository

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/skxm03/kr0n-backend/control-plane/internal/secrets/domain"
)

// SecretsRepository defines persistence queries for the dedicated Secrets microservice.
// It is a pure persistence seam: all secret data crossing this interface is already encrypted
// domain entities, ensuring plaintext and cryptographic algorithms never leak into storage.
type SecretsRepository interface {
	GetProjectKey(ctx context.Context, projectID uuid.UUID) (*domain.ProjectKey, error)
	GetOrCreateProjectKey(ctx context.Context, candidate domain.ProjectKey) (*domain.ProjectKey, error)
	UpsertEncryptedEnvVars(ctx context.Context, projectID uuid.UUID, environment string, vars []domain.ProjectEnvVar) ([]domain.EnvVarMetadata, error)
	ListEnvVars(ctx context.Context, orgID, projectID uuid.UUID, environment string) ([]domain.EnvVarMetadata, error)
	GetEncryptedEnvVars(ctx context.Context, projectID uuid.UUID, environment string) ([]domain.ProjectEnvVar, error)
	DeleteEnvVar(ctx context.Context, orgID, projectID uuid.UUID, environment, key string) error
}

// PostgresSecretsRepository implements SecretsRepository backed by PostgreSQL.
type PostgresSecretsRepository struct {
	pool *pgxpool.Pool
}

// NewPostgresSecretsRepository creates a PostgresSecretsRepository backed by pgxpool.
func NewPostgresSecretsRepository(pool *pgxpool.Pool) *PostgresSecretsRepository {
	return &PostgresSecretsRepository{pool: pool}
}

// GetProjectKey loads the encrypted DEK metadata for projectID from project_keys.
func (r *PostgresSecretsRepository) GetProjectKey(ctx context.Context, projectID uuid.UUID) (*domain.ProjectKey, error) {
	var pk domain.ProjectKey
	err := r.pool.QueryRow(ctx, `
		SELECT project_id, encrypted_dek, nonce, dek_version, kek_version, created_at, updated_at
		FROM project_keys
		WHERE project_id = $1;
	`, projectID).Scan(
		&pk.ProjectID,
		&pk.EncryptedDEK,
		&pk.Nonce,
		&pk.DEKVersion,
		&pk.KEKVersion,
		&pk.CreatedAt,
		&pk.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domain.ErrProjectKeyNotFound
		}
		return nil, fmt.Errorf("query project key: %w", err)
	}
	return &pk, nil
}

// GetOrCreateProjectKey atomically persists candidate project key or returns the existing row on conflict.
func (r *PostgresSecretsRepository) GetOrCreateProjectKey(
	ctx context.Context,
	candidate domain.ProjectKey,
) (*domain.ProjectKey, error) {
	var pk domain.ProjectKey
	err := r.pool.QueryRow(ctx, `
		INSERT INTO project_keys (
			project_id, encrypted_dek, nonce, dek_version, kek_version, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, now(), now())
		ON CONFLICT (project_id) DO UPDATE
			SET project_id = EXCLUDED.project_id
		RETURNING project_id, encrypted_dek, nonce, dek_version, kek_version, created_at, updated_at;
	`, candidate.ProjectID, candidate.EncryptedDEK, candidate.Nonce, candidate.DEKVersion, candidate.KEKVersion).Scan(
		&pk.ProjectID,
		&pk.EncryptedDEK,
		&pk.Nonce,
		&pk.DEKVersion,
		&pk.KEKVersion,
		&pk.CreatedAt,
		&pk.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("get or create project key: %w", err)
	}
	return &pk, nil
}

// UpsertEncryptedEnvVars batch-upserts already-encrypted environment variables into project_env_vars.
func (r *PostgresSecretsRepository) UpsertEncryptedEnvVars(
	ctx context.Context,
	projectID uuid.UUID,
	environment string,
	vars []domain.ProjectEnvVar,
) ([]domain.EnvVarMetadata, error) {
	if len(vars) == 0 {
		return []domain.EnvVarMetadata{}, nil
	}

	tx, err := r.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback(ctx)

	out := make([]domain.EnvVarMetadata, 0, len(vars))
	now := time.Now().UTC()

	for _, v := range vars {
		var meta domain.EnvVarMetadata
		err = tx.QueryRow(ctx, `
			INSERT INTO project_env_vars (
				id, project_id, environment, key, encrypted_value, nonce, dek_version, created_at, updated_at
			) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $8)
			ON CONFLICT (project_id, environment, key)
			DO UPDATE SET
				encrypted_value = EXCLUDED.encrypted_value,
				nonce           = EXCLUDED.nonce,
				dek_version     = EXCLUDED.dek_version,
				updated_at      = EXCLUDED.updated_at
			RETURNING id, project_id, environment, key, dek_version, created_at, updated_at;
		`, uuid.New(), projectID, environment, v.Key, v.EncryptedValue, v.Nonce, v.DEKVersion, now).Scan(
			&meta.ID, &meta.ProjectID, &meta.Environment, &meta.Key,
			&meta.DEKVersion, &meta.CreatedAt, &meta.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("upsert encrypted env var %q: %w", v.Key, err)
		}
		meta.MaskedValue = domain.MaskedSecretPlaceholder
		meta.HasValue = true
		out = append(out, meta)
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit upsert encrypted env vars: %w", err)
	}
	return out, nil
}

// ListEnvVars returns masked metadata for all environment variables in (orgID, projectID, environment) ordered alphabetically by key.
func (r *PostgresSecretsRepository) ListEnvVars(
	ctx context.Context,
	orgID, projectID uuid.UUID,
	environment string,
) ([]domain.EnvVarMetadata, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT id, project_id, environment, key, dek_version, created_at, updated_at
		FROM project_env_vars
		WHERE project_id = $1 AND environment = $2
		ORDER BY key ASC;
	`, projectID, environment)
	if err != nil {
		return nil, fmt.Errorf("query project env vars: %w", err)
	}
	defer rows.Close()

	var out []domain.EnvVarMetadata
	for rows.Next() {
		var m domain.EnvVarMetadata
		if err := rows.Scan(&m.ID, &m.ProjectID, &m.Environment, &m.Key, &m.DEKVersion, &m.CreatedAt, &m.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan project env var metadata: %w", err)
		}
		m.MaskedValue = domain.MaskedSecretPlaceholder
		m.HasValue = true
		out = append(out, m)
	}
	return out, rows.Err()
}

// GetEncryptedEnvVars returns all encrypted environment variables for (projectID, environment).
func (r *PostgresSecretsRepository) GetEncryptedEnvVars(
	ctx context.Context,
	projectID uuid.UUID,
	environment string,
) ([]domain.ProjectEnvVar, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT id, project_id, environment, key, encrypted_value, nonce, dek_version, created_at, updated_at
		FROM project_env_vars
		WHERE project_id = $1 AND environment = $2
		ORDER BY key ASC;
	`, projectID, environment)
	if err != nil {
		return nil, fmt.Errorf("query encrypted env vars: %w", err)
	}
	defer rows.Close()

	var out []domain.ProjectEnvVar
	for rows.Next() {
		var v domain.ProjectEnvVar
		if err := rows.Scan(
			&v.ID, &v.ProjectID, &v.Environment, &v.Key,
			&v.EncryptedValue, &v.Nonce, &v.DEKVersion,
			&v.CreatedAt, &v.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan encrypted env var: %w", err)
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// DeleteEnvVar deletes a single environment variable by key in (orgID, projectID, environment).
func (r *PostgresSecretsRepository) DeleteEnvVar(
	ctx context.Context,
	orgID, projectID uuid.UUID,
	environment, key string,
) error {
	tag, err := r.pool.Exec(ctx, `
		DELETE FROM project_env_vars
		WHERE project_id = $1 AND environment = $2 AND key = $3;
	`, projectID, environment, key)
	if err != nil {
		return fmt.Errorf("delete project env var: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return domain.ErrEnvVarNotFound
	}
	return nil
}
