-- 1. users
CREATE TABLE users (
    id UUID PRIMARY KEY,
    email TEXT NOT NULL,
    email_verified_at TIMESTAMPTZ,
    display_name TEXT NOT NULL,
    avatar_url TEXT,
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended', 'deactivated')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT users_email_key UNIQUE (email),
    CONSTRAINT users_email_canonical CHECK (email = LOWER(TRIM(email))),
    CONSTRAINT users_display_name_check CHECK (LENGTH(TRIM(display_name)) >= 1)
);

-- 2. password_credentials
CREATE TABLE password_credentials (
    user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    password_hash TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT password_hash_non_empty CHECK (LENGTH(password_hash) > 0)
);

-- 3. oauth_identities
CREATE TABLE oauth_identities (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider TEXT NOT NULL CHECK (provider IN ('github', 'google')),
    provider_user_id TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT oauth_identities_provider_uid_key UNIQUE (provider, provider_user_id),
    CONSTRAINT oauth_identities_user_provider_key UNIQUE (user_id, provider)
);

-- 4. sessions
CREATE TABLE sessions (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL,
    user_agent TEXT,
    ip_address INET,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT sessions_token_hash_key UNIQUE (token_hash)
);

CREATE INDEX sessions_user_active_idx ON sessions (user_id, last_seen_at DESC) 
WHERE revoked_at IS NULL;

-- 5. email_verification_tokens
CREATE TABLE email_verification_tokens (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT email_verification_tokens_token_hash_key UNIQUE (token_hash)
);

CREATE INDEX email_verification_tokens_user_active_idx ON email_verification_tokens (user_id) 
WHERE consumed_at IS NULL;

-- 6. organizations
CREATE TABLE organizations (
    id UUID PRIMARY KEY,
    name TEXT NOT NULL,
    slug TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT organizations_slug_key UNIQUE (slug),
    CONSTRAINT organizations_name_check CHECK (LENGTH(TRIM(name)) >= 1),
    CONSTRAINT organizations_slug_canonical CHECK (slug = LOWER(TRIM(slug)))
);

-- 7. roles
CREATE TABLE roles (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT roles_id_canonical CHECK (id = LOWER(TRIM(id)))
);

-- 8. permissions
CREATE TABLE permissions (
    id TEXT PRIMARY KEY,
    description TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT permissions_id_canonical CHECK (id = LOWER(TRIM(id)))
);

-- 9. role_permissions
CREATE TABLE role_permissions (
    role_id TEXT NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    permission_id TEXT NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    PRIMARY KEY (role_id, permission_id)
);

CREATE INDEX role_permissions_permission_idx ON role_permissions (permission_id);

-- 10. organization_memberships
CREATE TABLE organization_memberships (
    id UUID PRIMARY KEY,
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id TEXT NOT NULL REFERENCES roles(id) ON DELETE RESTRICT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT org_memberships_org_user_key UNIQUE (organization_id, user_id)
);

CREATE INDEX org_memberships_user_idx ON organization_memberships (user_id);

-- 11. outbox_events
CREATE TABLE outbox_events (
    id UUID PRIMARY KEY,
    event_type TEXT NOT NULL,
    aggregate_type TEXT NOT NULL,
    aggregate_id UUID NOT NULL,
    payload JSONB NOT NULL,
    headers JSONB NOT NULL DEFAULT '{}'::jsonb,
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'processing', 'published', 'failed')),
    retry_count INTEGER NOT NULL DEFAULT 0 CHECK (retry_count >= 0),
    last_error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    scheduled_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    published_at TIMESTAMPTZ,

    CONSTRAINT outbox_events_payload_object CHECK (jsonb_typeof(payload) = 'object'),
    CONSTRAINT outbox_events_headers_object CHECK (jsonb_typeof(headers) = 'object')
);

CREATE INDEX outbox_events_pending_idx ON outbox_events (scheduled_at, created_at) 
WHERE status IN ('pending', 'failed');

-- Initial Roles Seed Data
INSERT INTO roles (id, name, description) VALUES
    ('owner',  'Owner',  'Full administrative control over the organization, billing, and membership.'),
    ('admin',  'Admin',  'Can manage organization settings, projects, and members, but cannot delete the organization.'),
    ('member', 'Member', 'Standard organization member with read access and project access.');

-- Initial Permissions Seed Data
INSERT INTO permissions (id, description) VALUES
    ('org:read',       'View organization details and settings.'),
    ('org:update',     'Update organization name and configuration.'),
    ('org:delete',     'Permanently delete the organization.'),
    ('member:read',    'View organization members and roles.'),
    ('member:create',  'Invite or add new members to the organization.'),
    ('member:update',  'Modify member roles within the organization.'),
    ('member:delete',  'Remove members from the organization.');

-- Initial Role to Permission Mappings
INSERT INTO role_permissions (role_id, permission_id) VALUES
    ('owner', 'org:read'),
    ('owner', 'org:update'),
    ('owner', 'org:delete'),
    ('owner', 'member:read'),
    ('owner', 'member:create'),
    ('owner', 'member:update'),
    ('owner', 'member:delete'),

    ('admin', 'org:read'),
    ('admin', 'org:update'),
    ('admin', 'member:read'),
    ('admin', 'member:create'),
    ('admin', 'member:update'),
    ('admin', 'member:delete'),

    ('member', 'org:read'),
    ('member', 'member:read');
