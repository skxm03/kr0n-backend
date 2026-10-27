-- 1. Login throttling & temporary lockout on users
ALTER TABLE users
    ADD COLUMN failed_login_attempts INT NOT NULL DEFAULT 0 CHECK (failed_login_attempts >= 0),
    ADD COLUMN locked_until TIMESTAMPTZ;

-- 2. Refresh-token rotation history (for token reuse detection)
CREATE TABLE refresh_token_history (
    token_hash TEXT PRIMARY KEY,
    session_id UUID NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    rotated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX refresh_token_history_session_idx ON refresh_token_history (session_id);
CREATE INDEX refresh_token_history_user_idx ON refresh_token_history (user_id);

-- 3. Password reset tokens (SHA-256 hash stored, single-use)
CREATE TABLE password_reset_tokens (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT password_reset_tokens_token_hash_key UNIQUE (token_hash)
);

CREATE INDEX password_reset_tokens_user_active_idx ON password_reset_tokens (user_id)
WHERE consumed_at IS NULL;

-- 4. API tokens (kr0n_pat_<random>, SHA-256 hash stored, org-scoped, permission subset)
CREATE TABLE api_tokens (
    id UUID PRIMARY KEY,
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    created_by_user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name TEXT NOT NULL CHECK (LENGTH(TRIM(name)) >= 1),
    token_prefix TEXT NOT NULL,
    token_hash TEXT NOT NULL,
    permissions TEXT[] NOT NULL DEFAULT '{}',
    expires_at TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT api_tokens_token_hash_key UNIQUE (token_hash)
);

CREATE INDEX api_tokens_org_active_idx ON api_tokens (organization_id, created_at DESC)
WHERE revoked_at IS NULL;
CREATE INDEX api_tokens_creator_idx ON api_tokens (created_by_user_id);

-- 5. Organization invites
CREATE TABLE organization_invites (
    id UUID PRIMARY KEY,
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    email TEXT NOT NULL,
    role_id TEXT NOT NULL REFERENCES roles(id) ON DELETE RESTRICT,
    invited_by_user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    accepted_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT organization_invites_token_hash_key UNIQUE (token_hash),
    CONSTRAINT organization_invites_email_canonical CHECK (email = LOWER(TRIM(email)))
);

CREATE INDEX organization_invites_org_pending_idx ON organization_invites (organization_id)
WHERE accepted_at IS NULL AND revoked_at IS NULL;
CREATE INDEX organization_invites_inviter_idx ON organization_invites (invited_by_user_id);

-- 6. Append-only audit events
-- Note: In production, application DB role should only have SELECT, INSERT on audit_events (no UPDATE/DELETE).
CREATE TABLE audit_events (
    id UUID PRIMARY KEY,
    organization_id UUID REFERENCES organizations(id) ON DELETE SET NULL,
    actor_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    actor_type TEXT NOT NULL DEFAULT 'user' CHECK (actor_type IN ('user', 'api_token', 'system')),
    action TEXT NOT NULL CHECK (LENGTH(TRIM(action)) >= 1),
    resource_type TEXT NOT NULL CHECK (LENGTH(TRIM(resource_type)) >= 1),
    resource_id TEXT,
    ip_address INET,
    user_agent TEXT,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX audit_events_org_created_idx ON audit_events (organization_id, created_at DESC);
CREATE INDEX audit_events_actor_created_idx ON audit_events (actor_user_id, created_at DESC);

-- 7. Additional RBAC permissions (project, environment, service, apitoken, audit)
INSERT INTO permissions (id, description) VALUES
    ('project:read',       'View projects in the organization.'),
    ('project:create',     'Create projects in the organization.'),
    ('project:update',     'Update projects in the organization.'),
    ('project:delete',     'Delete projects in the organization.'),
    ('environment:read',   'View environments.'),
    ('environment:create', 'Create environments.'),
    ('environment:update', 'Update environments.'),
    ('environment:delete', 'Delete environments.'),
    ('service:read',       'View services and deployments.'),
    ('service:create',     'Create and deploy services.'),
    ('service:update',     'Update services and trigger deployments.'),
    ('service:delete',     'Delete services.'),
    ('apitoken:read',      'View organization API tokens.'),
    ('apitoken:create',    'Create organization API tokens.'),
    ('apitoken:delete',    'Revoke organization API tokens.'),
    ('audit:read',         'View organization audit logs.')
ON CONFLICT (id) DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id) VALUES
    ('owner', 'project:read'), ('owner', 'project:create'), ('owner', 'project:update'), ('owner', 'project:delete'),
    ('owner', 'environment:read'), ('owner', 'environment:create'), ('owner', 'environment:update'), ('owner', 'environment:delete'),
    ('owner', 'service:read'), ('owner', 'service:create'), ('owner', 'service:update'), ('owner', 'service:delete'),
    ('owner', 'apitoken:read'), ('owner', 'apitoken:create'), ('owner', 'apitoken:delete'),
    ('owner', 'audit:read'),

    ('admin', 'project:read'), ('admin', 'project:create'), ('admin', 'project:update'), ('admin', 'project:delete'),
    ('admin', 'environment:read'), ('admin', 'environment:create'), ('admin', 'environment:update'), ('admin', 'environment:delete'),
    ('admin', 'service:read'), ('admin', 'service:create'), ('admin', 'service:update'), ('admin', 'service:delete'),
    ('admin', 'apitoken:read'), ('admin', 'apitoken:create'), ('admin', 'apitoken:delete'),
    ('admin', 'audit:read'),

    ('member', 'project:read'),
    ('member', 'environment:read'),
    ('member', 'service:read'), ('member', 'service:create'), ('member', 'service:update')
ON CONFLICT (role_id, permission_id) DO NOTHING;

