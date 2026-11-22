CREATE TABLE IF NOT EXISTS projects (
    id UUID PRIMARY KEY,
    organization_id UUID NOT NULL,
    name TEXT NOT NULL CHECK (LENGTH(TRIM(name)) >= 1),
    slug TEXT NOT NULL CHECK (LENGTH(TRIM(slug)) >= 2),
    description TEXT NOT NULL DEFAULT '',
    github_installation_id BIGINT NOT NULL,
    repo_id BIGINT,
    repo_owner TEXT NOT NULL CHECK (LENGTH(TRIM(repo_owner)) >= 1),
    repo_name TEXT NOT NULL CHECK (LENGTH(TRIM(repo_name)) >= 1),
    production_branch TEXT NOT NULL DEFAULT 'main' CHECK (LENGTH(TRIM(production_branch)) >= 1),
    root_directory TEXT NOT NULL DEFAULT '/' CHECK (root_directory LIKE '/%'),
    application_preset TEXT NOT NULL DEFAULT 'auto' CHECK (LENGTH(TRIM(application_preset)) >= 1),
    revision BIGINT NOT NULL DEFAULT 1 CHECK (revision >= 1),
    created_by_user_id UUID,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT projects_org_slug_key UNIQUE (organization_id, slug)
);

CREATE INDEX IF NOT EXISTS projects_org_created_idx ON projects (organization_id, created_at DESC);
CREATE INDEX IF NOT EXISTS projects_installation_idx ON projects (github_installation_id);
