package service

import (
	"context"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	authv1 "github.com/skxm03/kr0n-backend/control-plane/gen/auth/v1"
	githubv1 "github.com/skxm03/kr0n-backend/control-plane/gen/github/v1"
	"github.com/skxm03/kr0n-backend/control-plane/pkg/authz"
)

// Authorizer evaluates whether caller principal p holds a permission in orgID.
type Authorizer = authz.Authorizer

// AuthClientAuthorizer evaluates permissions by calling AuthService.CheckPermission over gRPC.
type AuthClientAuthorizer = authz.AuthClientAuthorizer

// NewAuthClientAuthorizer creates an AuthClientAuthorizer backed by an AuthService gRPC client.
var NewAuthClientAuthorizer = authz.NewAuthClientAuthorizer

// LocalDBAuthorizer evaluates permissions directly against a Postgres pool (for testdb/monolith mode).
type LocalDBAuthorizer = authz.LocalDBAuthorizer

// NewLocalDBAuthorizer creates a LocalDBAuthorizer backed by a pgxpool.Pool.
var NewLocalDBAuthorizer = authz.NewLocalDBAuthorizer

// InstallationVerifier checks whether a GitHub installation is linked to orgID and active.
type InstallationVerifier interface {
	VerifyActiveOrgInstallation(ctx context.Context, orgID uuid.UUID, installationID int64) (bool, error)
}

// GitHubClientInstallationVerifier verifies GitHub installations by calling GitHubService.ListGitHubInstallations over gRPC.
type GitHubClientInstallationVerifier struct {
	client githubv1.GitHubServiceClient
}

// NewGitHubClientInstallationVerifier creates a GitHubClientInstallationVerifier backed by a GitHubService gRPC client.
func NewGitHubClientInstallationVerifier(client githubv1.GitHubServiceClient) *GitHubClientInstallationVerifier {
	return &GitHubClientInstallationVerifier{client: client}
}

func (v *GitHubClientInstallationVerifier) VerifyActiveOrgInstallation(ctx context.Context, orgID uuid.UUID, installationID int64) (bool, error) {
	resp, err := v.client.ListGitHubInstallations(ctx, &githubv1.ListGitHubInstallationsRequest{
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
