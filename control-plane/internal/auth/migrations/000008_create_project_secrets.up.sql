CREATE TABLE project_keys (
    project_id UUID PRIMARY KEY REFERENCES projects(id) ON DELETE CASCADE,
    encrypted_dek BYTEA NOT NULL,
    nonce BYTEA NOT NULL,
    dek_version INT NOT NULL DEFAULT 1,
    kek_version INT NOT NULL DEFAULT 1,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE project_env_vars (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    environment TEXT NOT NULL DEFAULT 'production' CHECK (LENGTH(TRIM(environment)) >= 1),
    key TEXT NOT NULL CHECK (LENGTH(TRIM(key)) >= 1 AND key ~ '^[a-zA-Z_][a-zA-Z0-9_]*$'),
    encrypted_value BYTEA NOT NULL,
    nonce BYTEA NOT NULL,
    dek_version INT NOT NULL DEFAULT 1,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT project_env_vars_unique UNIQUE (project_id, environment, key)
);

CREATE INDEX project_env_vars_project_env_idx ON project_env_vars (project_id, environment);
