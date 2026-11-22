package service

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	authv1 "github.com/skxm03/kr0n-backend/control-plane/gen/auth/v1"
	"github.com/skxm03/kr0n-backend/control-plane/internal/servicemanager/domain"
)

// Authorizer evaluates whether caller principal p holds a permission in orgID.
type Authorizer interface {
	CheckPermission(ctx context.Context, p domain.Principal, orgID uuid.UUID, permission string) (bool, error)
}

// InstallationVerifier checks whether a GitHub installation is linked to orgID and active.
type InstallationVerifier interface {
	VerifyActiveOrgInstallation(ctx context.Context, orgID uuid.UUID, installationID int64) (bool, error)
}

// AuthClientAuthorizer evaluates permissions by calling AuthService.CheckPermission over gRPC.
type AuthClientAuthorizer struct {
	client authv1.AuthServiceClient
}

// NewAuthClientAuthorizer creates an AuthClientAuthorizer backed by an AuthService gRPC client.
func NewAuthClientAuthorizer(client authv1.AuthServiceClient) *AuthClientAuthorizer {
	return &AuthClientAuthorizer{client: client}
}

func (a *AuthClientAuthorizer) CheckPermission(ctx context.Context, p domain.Principal, orgID uuid.UUID, permission string) (bool, error) {
	resp, err := a.client.CheckPermission(ctx, &authv1.CheckPermissionRequest{
		Caller: &authv1.CallerPrincipal{
			UserId: p.UserID.String(),
			Kind:   p.Kind,
		},
		OrgId:      orgID.String(),
		Permission: permission,
	})
	if err != nil {
		return false, err
	}
	return resp.GetAllowed(), nil
}

// AuthClientInstallationVerifier verifies GitHub installations by calling AuthService.ListGitHubInstallations over gRPC.
type AuthClientInstallationVerifier struct {
	client authv1.AuthServiceClient
}

// NewAuthClientInstallationVerifier creates an AuthClientInstallationVerifier backed by an AuthService gRPC client.
func NewAuthClientInstallationVerifier(client authv1.AuthServiceClient) *AuthClientInstallationVerifier {
	return &AuthClientInstallationVerifier{client: client}
}

func (v *AuthClientInstallationVerifier) VerifyActiveOrgInstallation(ctx context.Context, orgID uuid.UUID, installationID int64) (bool, error) {
	resp, err := v.client.ListGitHubInstallations(ctx, &authv1.ListGitHubInstallationsRequest{
		Caller: &authv1.CallerPrincipal{
			Kind: "service",
		},
		OrgId: orgID.String(),
	})
	if err != nil {
		return false, err
	}
	for _, inst := range resp.GetInstallations() {
		if inst.GetInstallationId() == installationID && strings.EqualFold(inst.GetStatus(), "active") {
			return true, nil
		}
	}
	return false, nil
}

// LocalDBAuthorizer evaluates permissions directly against a Postgres pool (for testdb/monolith mode).
type LocalDBAuthorizer struct {
	pool *pgxpool.Pool
}

// NewLocalDBAuthorizer creates a LocalDBAuthorizer backed by a pgxpool.Pool.
func NewLocalDBAuthorizer(pool *pgxpool.Pool) *LocalDBAuthorizer {
	return &LocalDBAuthorizer{pool: pool}
}

func (a *LocalDBAuthorizer) CheckPermission(ctx context.Context, p domain.Principal, orgID uuid.UUID, permission string) (bool, error) {
	var roleID string
	err := a.pool.QueryRow(ctx, `
		SELECT role_id
		FROM organization_memberships
		WHERE organization_id = $1 AND user_id = $2;
	`, orgID, p.UserID).Scan(&roleID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, nil
		}
		return false, fmt.Errorf("query membership role: %w", err)
	}

	rows, err := a.pool.Query(ctx, `
		SELECT permission_id
		FROM role_permissions
		WHERE role_id = $1
		ORDER BY permission_id;
	`, roleID)
	if err != nil {
		return false, fmt.Errorf("query role permissions: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var perm string
		if err := rows.Scan(&perm); err != nil {
			return false, err
		}
		if perm == permission {
			return true, nil
		}
	}
	return false, rows.Err()
}

// LocalDBInstallationVerifier verifies installations against a Postgres pool (for testdb/monolith mode).
type LocalDBInstallationVerifier struct {
	pool *pgxpool.Pool
}

// NewLocalDBInstallationVerifier creates a LocalDBInstallationVerifier backed by a pgxpool.Pool.
func NewLocalDBInstallationVerifier(pool *pgxpool.Pool) *LocalDBInstallationVerifier {
	return &LocalDBInstallationVerifier{pool: pool}
}

func (v *LocalDBInstallationVerifier) VerifyActiveOrgInstallation(ctx context.Context, orgID uuid.UUID, installationID int64) (bool, error) {
	var exists bool
	err := v.pool.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1
			FROM github_installations
			WHERE organization_id = $1
			  AND installation_id = $2
			  AND status = 'active'
		);
	`, orgID, installationID).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("verify active github installation: %w", err)
	}
	return exists, nil
}
