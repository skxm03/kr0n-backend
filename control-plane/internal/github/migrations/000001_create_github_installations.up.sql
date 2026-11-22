CREATE TABLE IF NOT EXISTS github_installations (
    id UUID PRIMARY KEY,
    organization_id UUID NOT NULL,
    installation_id BIGINT NOT NULL,
    account_login TEXT NOT NULL CHECK (LENGTH(TRIM(account_login)) >= 1),
    account_type TEXT NOT NULL DEFAULT 'Organization' CHECK (account_type IN ('Organization', 'User')),
    repository_selection TEXT NOT NULL DEFAULT 'all' CHECK (repository_selection IN ('all', 'selected')),
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended', 'uninstalled', 'deleted')),
    created_by_user_id UUID,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT github_installations_installation_id_key UNIQUE (installation_id)
);

CREATE INDEX IF NOT EXISTS github_installations_org_idx ON github_installations (organization_id, created_at DESC);
