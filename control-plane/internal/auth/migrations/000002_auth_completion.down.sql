DELETE FROM role_permissions WHERE permission_id IN (
    'project:read', 'project:create', 'project:update', 'project:delete',
    'environment:read', 'environment:create', 'environment:update', 'environment:delete',
    'service:read', 'service:create', 'service:update', 'service:delete',
    'apitoken:read', 'apitoken:create', 'apitoken:delete',
    'audit:read'
);

DELETE FROM permissions WHERE id IN (
    'project:read', 'project:create', 'project:update', 'project:delete',
    'environment:read', 'environment:create', 'environment:update', 'environment:delete',
    'service:read', 'service:create', 'service:update', 'service:delete',
    'apitoken:read', 'apitoken:create', 'apitoken:delete',
    'audit:read'
);

DROP TABLE IF EXISTS audit_events;
DROP TABLE IF EXISTS organization_invites;
DROP TABLE IF EXISTS api_tokens;
DROP TABLE IF EXISTS password_reset_tokens;
DROP TABLE IF EXISTS refresh_token_history;

ALTER TABLE users
    DROP COLUMN IF EXISTS locked_until,
    DROP COLUMN IF EXISTS failed_login_attempts;

