package repository

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/skxm03/kr0n-backend/control-plane/internal/secrets/crypto"
	"github.com/skxm03/kr0n-backend/control-plane/internal/secrets/domain"
)

// SecretsRepository defines persistence queries for the dedicated Secrets microservice.
type SecretsRepository interface {
	GetOrCreateProjectDEK(ctx context.Context, projectID uuid.UUID, km *crypto.KeyManager) ([]byte, int, error)
	UpsertEnvVars(ctx context.Context, orgID, projectID uuid.UUID, environment string, inputs []domain.EnvVarInput, km *crypto.KeyManager) ([]domain.EnvVarMetadata, error)
	ListEnvVars(ctx context.Context, orgID, projectID uuid.UUID, environment string) ([]domain.EnvVarMetadata, error)
	DeleteEnvVar(ctx context.Context, orgID, projectID uuid.UUID, environment, key string) error
	ResolvePlaintextSecrets(ctx context.Context, projectID uuid.UUID, environment string, km *crypto.KeyManager) (map[string]string, error)
}

// PostgresSecretsRepository implements SecretsRepository backed by PostgreSQL.
type PostgresSecretsRepository struct {
	pool *pgxpool.Pool
}

// NewPostgresSecretsRepository creates a PostgresSecretsRepository backed by pgxpool.
func NewPostgresSecretsRepository(pool *pgxpool.Pool) *PostgresSecretsRepository {
	return &PostgresSecretsRepository{pool: pool}
}

func (r *PostgresSecretsRepository) getOrCreateProjectDEKTx(
	ctx context.Context,
	tx pgx.Tx,
	projectID uuid.UUID,
	km *crypto.KeyManager,
) (dek []byte, dekVersion int, err error) {
	if km == nil {
		return nil, 0, domain.ErrMasterKeyNotConfigured
	}

	var (
		encDEK []byte
		nonce  []byte
		dekVer int
		kekVer int
	)

	err = tx.QueryRow(ctx, `
		SELECT encrypted_dek, nonce, dek_version, kek_version
		FROM project_keys
		WHERE project_id = $1
		FOR UPDATE;
	`, projectID).Scan(&encDEK, &nonce, &dekVer, &kekVer)

	if errors.Is(err, pgx.ErrNoRows) {
		candidateDEK, genErr := crypto.GenerateRandomKey()
		if genErr != nil {
			return nil, 0, fmt.Errorf("generate project dek: %w", genErr)
		}
		candidateEnc, candidateNonce, wrapErr := km.WrapDEK(projectID, candidateDEK)
		if wrapErr != nil {
			return nil, 0, fmt.Errorf("wrap project dek: %w", wrapErr)
		}

		_, execErr := tx.Exec(ctx, `
			INSERT INTO project_keys (
				project_id, encrypted_dek, nonce, dek_version, kek_version, created_at, updated_at
			) VALUES ($1, $2, $3, 1, $4, now(), now())
			ON CONFLICT (project_id) DO NOTHING;
		`, projectID, candidateEnc, candidateNonce, km.KEKVersion())
		if execErr != nil {
			return nil, 0, fmt.Errorf("atomic insert project dek: %w", execErr)
		}

		err = tx.QueryRow(ctx, `
			SELECT encrypted_dek, nonce, dek_version, kek_version
			FROM project_keys
			WHERE project_id = $1
			FOR UPDATE;
		`, projectID).Scan(&encDEK, &nonce, &dekVer, &kekVer)
	}

	if err != nil {
		return nil, 0, fmt.Errorf("query locked project dek: %w", err)
	}

	if kekVer != km.KEKVersion() {
		// Future proof: rewrap with newer master KEK if rotated
	}

	dek, err = km.UnwrapDEK(projectID, encDEK, nonce)
	if err != nil {
		return nil, 0, fmt.Errorf("unwrap project dek: %w", err)
	}
	return dek, dekVer, nil
}

// GetOrCreateProjectDEK returns the decrypted 256-bit AES DEK for projectID, atomically generating and persisting
// a new encrypted DEK under the master KEK if one does not already exist.
func (r *PostgresSecretsRepository) GetOrCreateProjectDEK(
	ctx context.Context,
	projectID uuid.UUID,
	km *crypto.KeyManager,
) ([]byte, int, error) {
	tx, err := r.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return nil, 0, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback(ctx)

	dek, dekVer, err := r.getOrCreateProjectDEKTx(ctx, tx, projectID, km)
	if err != nil {
		return nil, 0, err
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, 0, fmt.Errorf("commit get or create project dek: %w", err)
	}
	return dek, dekVer, nil
}

// UpsertEnvVars resolves/creates the project's DEK, encrypts all input variables with AES-256-GCM + AAD
// (`<project_id>:<environment>:<key>`), upserts them into `project_env_vars`, and returns the masked metadata list.
func (r *PostgresSecretsRepository) UpsertEnvVars(
	ctx context.Context,
	orgID, projectID uuid.UUID,
	environment string,
	inputs []domain.EnvVarInput,
	km *crypto.KeyManager,
) ([]domain.EnvVarMetadata, error) {
	if km == nil {
		return nil, domain.ErrMasterKeyNotConfigured
	}

	tx, err := r.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback(ctx)

	dek, dekVer, err := r.getOrCreateProjectDEKTx(ctx, tx, projectID, km)
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	out := make([]domain.EnvVarMetadata, 0, len(inputs))

	for _, in := range inputs {
		ct, nonce, encErr := crypto.EncryptSecret(dek, projectID, environment, in.Key, in.Value)
		if encErr != nil {
			return nil, fmt.Errorf("encrypt secret %q: %w", in.Key, encErr)
		}

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
		`, uuid.New(), projectID, environment, in.Key, ct, nonce, dekVer, now).Scan(
			&meta.ID, &meta.ProjectID, &meta.Environment, &meta.Key,
			&meta.DEKVersion, &meta.CreatedAt, &meta.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("upsert env var %q: %w", in.Key, err)
		}
		meta.MaskedValue = domain.MaskedSecretPlaceholder
		meta.HasValue = true
		out = append(out, meta)
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit upsert env vars: %w", err)
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

// ResolvePlaintextSecrets is the internal repository method backing resolver.SecretResolver.
func (r *PostgresSecretsRepository) ResolvePlaintextSecrets(
	ctx context.Context,
	projectID uuid.UUID,
	environment string,
	km *crypto.KeyManager,
) (map[string]string, error) {
	if km == nil {
		return nil, domain.ErrMasterKeyNotConfigured
	}

	var (
		encDEK []byte
		nonce  []byte
	)
	err := r.pool.QueryRow(ctx, `
		SELECT encrypted_dek, nonce
		FROM project_keys
		WHERE project_id = $1;
	`, projectID).Scan(&encDEK, &nonce)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return map[string]string{}, nil
		}
		return nil, fmt.Errorf("query project key: %w", err)
	}

	dek, err := km.UnwrapDEK(projectID, encDEK, nonce)
	if err != nil {
		return nil, fmt.Errorf("unwrap project dek: %w", err)
	}

	rows, err := r.pool.Query(ctx, `
		SELECT key, encrypted_value, nonce
		FROM project_env_vars
		WHERE project_id = $1 AND environment = $2
		ORDER BY key ASC;
	`, projectID, environment)
	if err != nil {
		return nil, fmt.Errorf("query encrypted env vars: %w", err)
	}
	defer rows.Close()

	secrets := make(map[string]string)
	for rows.Next() {
		var (
			k     string
			ct    []byte
			vNonc []byte
		)
		if err := rows.Scan(&k, &ct, &vNonc); err != nil {
			return nil, fmt.Errorf("scan encrypted env var: %w", err)
		}
		plain, decErr := crypto.DecryptSecret(dek, projectID, environment, k, ct, vNonc)
		if decErr != nil {
			return nil, fmt.Errorf("decrypt env var %q: %w", k, decErr)
		}
		secrets[k] = plain
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return secrets, nil
}
