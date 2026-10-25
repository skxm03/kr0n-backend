package org

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
	"github.com/skxm03/kr0n-backend/control-plane/internal/auth/user"
)

// PostgresRepository implements Repository using PostgreSQL.
type PostgresRepository struct {
	pool *pgxpool.Pool
}

// NewPostgresRepository creates a PostgresRepository backed by pgxpool.
func NewPostgresRepository(pool *pgxpool.Pool) *PostgresRepository {
	return &PostgresRepository{pool: pool}
}

// RolePermissions returns the user's role_id and granted permission_ids in orgID.
func (r *PostgresRepository) RolePermissions(ctx context.Context, userID, orgID uuid.UUID) (string, []string, error) {
	var roleID string
	err := r.pool.QueryRow(ctx, `
		SELECT role_id
		FROM organization_memberships
		WHERE organization_id = $1 AND user_id = $2;
	`, orgID, userID).Scan(&roleID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", nil, ErrMemberNotFound
		}
		return "", nil, fmt.Errorf("query membership role: %w", err)
	}

	rows, err := r.pool.Query(ctx, `
		SELECT permission_id
		FROM role_permissions
		WHERE role_id = $1
		ORDER BY permission_id;
	`, roleID)
	if err != nil {
		return "", nil, fmt.Errorf("query role permissions: %w", err)
	}
	defer rows.Close()

	var perms []string
	for rows.Next() {
		var p string
		if err := rows.Scan(&p); err != nil {
			return "", nil, err
		}
		perms = append(perms, p)
	}
	return roleID, perms, rows.Err()
}

// ListRoles returns all seeded roles and their permissions.
func (r *PostgresRepository) ListRoles(ctx context.Context) ([]Role, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT r.id, r.name, r.description,
		       COALESCE(array_agg(rp.permission_id ORDER BY rp.permission_id) FILTER (WHERE rp.permission_id IS NOT NULL), '{}')
		FROM roles r
		LEFT JOIN role_permissions rp ON rp.role_id = r.id
		GROUP BY r.id, r.name, r.description
		ORDER BY r.id;
	`)
	if err != nil {
		return nil, fmt.Errorf("list roles: %w", err)
	}
	defer rows.Close()

	var out []Role
	for rows.Next() {
		var role Role
		if err := rows.Scan(&role.ID, &role.Name, &role.Description, &role.Permissions); err != nil {
			return nil, err
		}
		out = append(out, role)
	}
	return out, rows.Err()
}

// CreateOrg inserts the organization and owner membership in a single transaction.
func (r *PostgresRepository) CreateOrg(ctx context.Context, o *Organization, ownerUserID uuid.UUID) error {
	tx, err := r.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback(ctx)

	_, err = tx.Exec(ctx, `
		INSERT INTO organizations (id, name, slug, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5);
	`, o.ID, o.Name, o.Slug, o.CreatedAt, o.UpdatedAt)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == pgerrcode.UniqueViolation {
			return ErrSlugAlreadyExists
		}
		return fmt.Errorf("insert organization: %w", err)
	}

	_, err = tx.Exec(ctx, `
		INSERT INTO organization_memberships (id, organization_id, user_id, role_id, created_at, updated_at)
		VALUES ($1, $2, $3, 'owner', $4, $4);
	`, uuid.New(), o.ID, ownerUserID, o.CreatedAt)
	if err != nil {
		return fmt.Errorf("insert owner membership: %w", err)
	}

	return tx.Commit(ctx)
}

// ListUserOrgs returns all organizations a user belongs to along with their role.
func (r *PostgresRepository) ListUserOrgs(ctx context.Context, userID uuid.UUID) ([]Organization, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT o.id, o.name, o.slug, om.role_id, o.created_at, o.updated_at
		FROM organizations o
		JOIN organization_memberships om ON om.organization_id = o.id
		WHERE om.user_id = $1
		ORDER BY o.created_at DESC;
	`, userID)
	if err != nil {
		return nil, fmt.Errorf("list user orgs: %w", err)
	}
	defer rows.Close()

	var out []Organization
	for rows.Next() {
		var o Organization
		if err := rows.Scan(&o.ID, &o.Name, &o.Slug, &o.RoleID, &o.CreatedAt, &o.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, o)
	}
	return out, rows.Err()
}

// GetOrg retrieves an organization by ID.
func (r *PostgresRepository) GetOrg(ctx context.Context, orgID uuid.UUID) (*Organization, error) {
	var o Organization
	err := r.pool.QueryRow(ctx, `
		SELECT id, name, slug, created_at, updated_at
		FROM organizations
		WHERE id = $1;
	`, orgID).Scan(&o.ID, &o.Name, &o.Slug, &o.CreatedAt, &o.UpdatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrOrgNotFound
		}
		return nil, fmt.Errorf("get organization: %w", err)
	}
	return &o, nil
}

// UpdateOrg updates an organization's name.
func (r *PostgresRepository) UpdateOrg(ctx context.Context, orgID uuid.UUID, name string, now time.Time) (*Organization, error) {
	var o Organization
	err := r.pool.QueryRow(ctx, `
		UPDATE organizations
		SET name = $1, updated_at = $2
		WHERE id = $3
		RETURNING id, name, slug, created_at, updated_at;
	`, name, now, orgID).Scan(&o.ID, &o.Name, &o.Slug, &o.CreatedAt, &o.UpdatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrOrgNotFound
		}
		return nil, fmt.Errorf("update organization: %w", err)
	}
	return &o, nil
}

// DeleteOrg permanently deletes an organization.
func (r *PostgresRepository) DeleteOrg(ctx context.Context, orgID uuid.UUID) error {
	tag, err := r.pool.Exec(ctx, `DELETE FROM organizations WHERE id = $1;`, orgID)
	if err != nil {
		return fmt.Errorf("delete organization: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrOrgNotFound
	}
	return nil
}

// ListMembers returns all members of an organization.
func (r *PostgresRepository) ListMembers(ctx context.Context, orgID uuid.UUID) ([]Member, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT u.id, u.email, u.display_name, om.role_id, om.created_at
		FROM organization_memberships om
		JOIN users u ON u.id = om.user_id
		WHERE om.organization_id = $1
		ORDER BY om.created_at ASC;
	`, orgID)
	if err != nil {
		return nil, fmt.Errorf("list members: %w", err)
	}
	defer rows.Close()

	var out []Member
	for rows.Next() {
		var m Member
		if err := rows.Scan(&m.UserID, &m.Email, &m.DisplayName, &m.RoleID, &m.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// AddMemberByEmail adds an existing user by email to orgID.
func (r *PostgresRepository) AddMemberByEmail(ctx context.Context, orgID uuid.UUID, email, roleID string, now time.Time) (*Member, error) {
	var m Member
	err := r.pool.QueryRow(ctx, `
		SELECT id, email, display_name
		FROM users
		WHERE email = $1;
	`, email).Scan(&m.UserID, &m.Email, &m.DisplayName)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, user.ErrUserNotFound
		}
		return nil, fmt.Errorf("find user by email: %w", err)
	}

	_, err = r.pool.Exec(ctx, `
		INSERT INTO organization_memberships (id, organization_id, user_id, role_id, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $5);
	`, uuid.New(), orgID, m.UserID, roleID, now)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == pgerrcode.UniqueViolation {
			return nil, ErrMemberAlreadyExists
		}
		return nil, fmt.Errorf("insert membership: %w", err)
	}
	m.RoleID = roleID
	m.CreatedAt = now
	return &m, nil
}

// UpdateMemberRole updates a member's role while preventing demotion of the last owner.
func (r *PostgresRepository) UpdateMemberRole(ctx context.Context, orgID, targetUserID uuid.UUID, roleID string, now time.Time) error {
	tx, err := r.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback(ctx)

	var currentRole string
	err = tx.QueryRow(ctx, `
		SELECT role_id
		FROM organization_memberships
		WHERE organization_id = $1 AND user_id = $2
		FOR UPDATE;
	`, orgID, targetUserID).Scan(&currentRole)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrMemberNotFound
		}
		return fmt.Errorf("query member role: %w", err)
	}

	if currentRole == "owner" && roleID != "owner" {
		if err := ensureMultipleOwners(ctx, tx, orgID); err != nil {
			return err
		}
	}

	_, err = tx.Exec(ctx, `
		UPDATE organization_memberships
		SET role_id = $1, updated_at = $2
		WHERE organization_id = $3 AND user_id = $4;
	`, roleID, now, orgID, targetUserID)
	if err != nil {
		return fmt.Errorf("update member role: %w", err)
	}

	return tx.Commit(ctx)
}

// RemoveMember removes a member while preventing removal of the last owner.
func (r *PostgresRepository) RemoveMember(ctx context.Context, orgID, targetUserID uuid.UUID) error {
	tx, err := r.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback(ctx)

	var currentRole string
	err = tx.QueryRow(ctx, `
		SELECT role_id
		FROM organization_memberships
		WHERE organization_id = $1 AND user_id = $2
		FOR UPDATE;
	`, orgID, targetUserID).Scan(&currentRole)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrMemberNotFound
		}
		return fmt.Errorf("query member role: %w", err)
	}

	if currentRole == "owner" {
		if err := ensureMultipleOwners(ctx, tx, orgID); err != nil {
			return err
		}
	}

	if _, err := tx.Exec(ctx, `
		DELETE FROM organization_memberships
		WHERE organization_id = $1 AND user_id = $2;
	`, orgID, targetUserID); err != nil {
		return fmt.Errorf("delete member: %w", err)
	}

	// Tokens created by the removed member must not outlive their membership. Done in the same
	// transaction so membership removal and token revocation are atomic.
	if _, err := tx.Exec(ctx, `
		UPDATE api_tokens
		SET revoked_at = COALESCE(revoked_at, now())
		WHERE organization_id = $1 AND created_by_user_id = $2;
	`, orgID, targetUserID); err != nil {
		return fmt.Errorf("revoke member api tokens: %w", err)
	}

	return tx.Commit(ctx)
}

func ensureMultipleOwners(ctx context.Context, tx pgx.Tx, orgID uuid.UUID) error {
	rows, err := tx.Query(ctx, `
		SELECT user_id
		FROM organization_memberships
		WHERE organization_id = $1 AND role_id = 'owner'
		FOR UPDATE;
	`, orgID)
	if err != nil {
		return fmt.Errorf("lock organization owners: %w", err)
	}
	defer rows.Close()

	count := 0
	for rows.Next() {
		count++
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if count <= 1 {
		return ErrLastOwner
	}
	return nil
}

// CreateInvite persists a new organization invite. It rejects invites for emails that already belong
// to a member, and revokes any earlier pending invite for the same org+email so only one is live.
func (r *PostgresRepository) CreateInvite(ctx context.Context, inv *Invite) error {
	tx, err := r.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback(ctx)

	var alreadyMember bool
	if err := tx.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM organization_memberships om
			JOIN users u ON u.id = om.user_id
			WHERE om.organization_id = $1 AND u.email = $2
		);
	`, inv.OrganizationID, inv.Email).Scan(&alreadyMember); err != nil {
		return fmt.Errorf("check existing member: %w", err)
	}
	if alreadyMember {
		return ErrMemberAlreadyExists
	}

	if _, err := tx.Exec(ctx, `
		UPDATE organization_invites SET revoked_at = $3
		WHERE organization_id = $1 AND email = $2 AND accepted_at IS NULL AND revoked_at IS NULL;
	`, inv.OrganizationID, inv.Email, inv.CreatedAt); err != nil {
		return fmt.Errorf("revoke previous invites: %w", err)
	}

	if _, err := tx.Exec(ctx, `
		INSERT INTO organization_invites (id, organization_id, email, role_id, invited_by_user_id, token_hash, expires_at, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8);
	`, inv.ID, inv.OrganizationID, inv.Email, inv.RoleID, inv.InvitedByUserID, inv.TokenHash, inv.ExpiresAt, inv.CreatedAt); err != nil {
		return fmt.Errorf("insert invite: %w", err)
	}
	return tx.Commit(ctx)
}

// AcceptInvite validates the invite token and matching user email, adds membership, and marks accepted_at.
func (r *PostgresRepository) AcceptInvite(ctx context.Context, userID uuid.UUID, tokenHash string, now time.Time) (*Organization, error) {
	tx, err := r.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback(ctx)

	var (
		invID      uuid.UUID
		orgID      uuid.UUID
		invEmail   string
		roleID     string
		expiresAt  time.Time
		acceptedAt *time.Time
		revokedAt  *time.Time
	)
	err = tx.QueryRow(ctx, `
		SELECT id, organization_id, email, role_id, expires_at, accepted_at, revoked_at
		FROM organization_invites
		WHERE token_hash = $1
		FOR UPDATE;
	`, tokenHash).Scan(&invID, &orgID, &invEmail, &roleID, &expiresAt, &acceptedAt, &revokedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrInvalidInviteToken
		}
		return nil, fmt.Errorf("query invite: %w", err)
	}
	if acceptedAt != nil || revokedAt != nil || !now.Before(expiresAt) {
		return nil, ErrInvalidInviteToken
	}

	var userEmail string
	if err := tx.QueryRow(ctx, `SELECT email FROM users WHERE id = $1;`, userID).Scan(&userEmail); err != nil {
		return nil, ErrInvalidInviteToken
	}
	if userEmail != invEmail {
		return nil, ErrForbidden
	}

	if _, err := tx.Exec(ctx, `
		UPDATE organization_invites
		SET accepted_at = $1
		WHERE id = $2;
	`, now, invID); err != nil {
		return nil, fmt.Errorf("mark invite accepted: %w", err)
	}

	// An existing membership keeps its current role; an invite must never silently change it.
	if _, err := tx.Exec(ctx, `
		INSERT INTO organization_memberships (id, organization_id, user_id, role_id, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $5)
		ON CONFLICT (organization_id, user_id) DO NOTHING;
	`, uuid.New(), orgID, userID, roleID, now); err != nil {
		return nil, fmt.Errorf("insert membership from invite: %w", err)
	}

	var o Organization
	if err := tx.QueryRow(ctx, `
		SELECT o.id, o.name, o.slug, om.role_id, o.created_at, o.updated_at
		FROM organizations o
		JOIN organization_memberships om ON om.organization_id = o.id AND om.user_id = $2
		WHERE o.id = $1;
	`, orgID, userID).Scan(&o.ID, &o.Name, &o.Slug, &o.RoleID, &o.CreatedAt, &o.UpdatedAt); err != nil {
		return nil, fmt.Errorf("load organization: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit invite acceptance: %w", err)
	}
	return &o, nil
}

// RevokeInvite marks a pending invite as revoked.
func (r *PostgresRepository) RevokeInvite(ctx context.Context, orgID, inviteID uuid.UUID, now time.Time) error {
	tag, err := r.pool.Exec(ctx, `
		UPDATE organization_invites
		SET revoked_at = COALESCE(revoked_at, $1)
		WHERE id = $2 AND organization_id = $3 AND accepted_at IS NULL;
	`, now, inviteID, orgID)
	if err != nil {
		return fmt.Errorf("revoke invite: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrInviteNotFound
	}
	return nil
}

// CreateAPIToken inserts an organization API token record.
func (r *PostgresRepository) CreateAPIToken(ctx context.Context, tok *APIToken) error {
	_, err := r.pool.Exec(ctx, `
		INSERT INTO api_tokens (id, organization_id, created_by_user_id, name, token_prefix, token_hash, permissions, expires_at, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9);
	`, tok.ID, tok.OrganizationID, tok.CreatedByUserID, tok.Name, tok.TokenPrefix, tok.TokenHash, tok.Permissions, tok.ExpiresAt, tok.CreatedAt)
	if err != nil {
		return fmt.Errorf("insert api token: %w", err)
	}
	return nil
}

// ListAPITokens returns all non-revoked API tokens for orgID.
func (r *PostgresRepository) ListAPITokens(ctx context.Context, orgID uuid.UUID) ([]APIToken, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT id, organization_id, created_by_user_id, name, token_prefix, permissions, expires_at, last_used_at, revoked_at, created_at
		FROM api_tokens
		WHERE organization_id = $1 AND revoked_at IS NULL
		ORDER BY created_at DESC;
	`, orgID)
	if err != nil {
		return nil, fmt.Errorf("list api tokens: %w", err)
	}
	defer rows.Close()

	var out []APIToken
	for rows.Next() {
		var t APIToken
		if err := rows.Scan(&t.ID, &t.OrganizationID, &t.CreatedByUserID, &t.Name, &t.TokenPrefix, &t.Permissions, &t.ExpiresAt, &t.LastUsedAt, &t.RevokedAt, &t.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// RevokeAPIToken marks an API token as revoked.
func (r *PostgresRepository) RevokeAPIToken(ctx context.Context, orgID, tokenID uuid.UUID, now time.Time) error {
	tag, err := r.pool.Exec(ctx, `
		UPDATE api_tokens
		SET revoked_at = COALESCE(revoked_at, $1)
		WHERE id = $2 AND organization_id = $3;
	`, now, tokenID, orgID)
	if err != nil {
		return fmt.Errorf("revoke api token: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrTokenNotFound
	}
	return nil
}

// GetAPITokenByHash retrieves an API token and its creator's user status by SHA-256 token hash.
func (r *PostgresRepository) GetAPITokenByHash(ctx context.Context, tokenHash string) (*APIToken, user.Status, error) {
	var (
		t         APIToken
		statusStr string
	)
	err := r.pool.QueryRow(ctx, `
		SELECT t.id, t.organization_id, t.created_by_user_id, t.name, t.token_prefix, t.token_hash,
		       t.permissions, t.expires_at, t.last_used_at, t.revoked_at, t.created_at,
		       u.status
		FROM api_tokens t
		JOIN users u ON u.id = t.created_by_user_id
		WHERE t.token_hash = $1;
	`, tokenHash).Scan(
		&t.ID, &t.OrganizationID, &t.CreatedByUserID, &t.Name, &t.TokenPrefix, &t.TokenHash,
		&t.Permissions, &t.ExpiresAt, &t.LastUsedAt, &t.RevokedAt, &t.CreatedAt,
		&statusStr,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, "", ErrTokenNotFound
		}
		return nil, "", fmt.Errorf("get api token by hash: %w", err)
	}
	return &t, user.Status(statusStr), nil
}

// TouchAPITokenLastUsed updates last_used_at for tokenID, skipping the write when it is already recent.
func (r *PostgresRepository) TouchAPITokenLastUsed(ctx context.Context, tokenID uuid.UUID, usedAt time.Time) error {
	_, err := r.pool.Exec(ctx, `
		UPDATE api_tokens SET last_used_at = $1
		WHERE id = $2 AND (last_used_at IS NULL OR last_used_at < $1 - make_interval(secs => $3));
	`, usedAt, tokenID, lastUsedWriteInterval.Seconds())
	return err
}
