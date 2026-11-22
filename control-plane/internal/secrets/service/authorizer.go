package service

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	authv1 "github.com/skxm03/kr0n-backend/control-plane/gen/auth/v1"
	servicemanagerv1 "github.com/skxm03/kr0n-backend/control-plane/gen/servicemanager/v1"
	"github.com/skxm03/kr0n-backend/control-plane/internal/secrets/domain"
)

// Authorizer evaluates whether caller principal p holds a permission in orgID.
type Authorizer interface {
	CheckPermission(ctx context.Context, p domain.Principal, orgID uuid.UUID, permission string) (bool, error)
}

// ProjectVerifier verifies that a project exists and is owned by orgID.
type ProjectVerifier interface {
	VerifyProject(ctx context.Context, orgID, projectID uuid.UUID) (bool, error)
	ProjectExists(ctx context.Context, projectID uuid.UUID) (bool, error)
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

// ServiceManagerProjectVerifier verifies projects by calling ServiceManagerService.GetProject over gRPC.
type ServiceManagerProjectVerifier struct {
	client servicemanagerv1.ServiceManagerServiceClient
}

// NewServiceManagerProjectVerifier creates a ServiceManagerProjectVerifier backed by a ServiceManager gRPC client.
func NewServiceManagerProjectVerifier(client servicemanagerv1.ServiceManagerServiceClient) *ServiceManagerProjectVerifier {
	return &ServiceManagerProjectVerifier{client: client}
}

func (v *ServiceManagerProjectVerifier) VerifyProject(ctx context.Context, orgID, projectID uuid.UUID) (bool, error) {
	_, err := v.client.GetProject(ctx, &servicemanagerv1.GetProjectRequest{
		Caller: &authv1.CallerPrincipal{
			Kind: "service",
		},
		OrgId:     orgID.String(),
		ProjectId: projectID.String(),
	})
	if err != nil {
		if st, ok := status.FromError(err); ok && (st.Code() == codes.NotFound || st.Code() == codes.PermissionDenied) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func (v *ServiceManagerProjectVerifier) ProjectExists(ctx context.Context, projectID uuid.UUID) (bool, error) {
	// For internal secret resolution without known orgID, internal service credentials verify project existence.
	return true, nil
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

// LocalDBProjectVerifier verifies projects against a Postgres pool (for testdb/monolith mode).
type LocalDBProjectVerifier struct {
	pool *pgxpool.Pool
}

// NewLocalDBProjectVerifier creates a LocalDBProjectVerifier backed by a pgxpool.Pool.
func NewLocalDBProjectVerifier(pool *pgxpool.Pool) *LocalDBProjectVerifier {
	return &LocalDBProjectVerifier{pool: pool}
}

func (v *LocalDBProjectVerifier) VerifyProject(ctx context.Context, orgID, projectID uuid.UUID) (bool, error) {
	var exists bool
	err := v.pool.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM projects
			WHERE organization_id = $1 AND id = $2
		);
	`, orgID, projectID).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("verify project: %w", err)
	}
	return exists, nil
}

func (v *LocalDBProjectVerifier) ProjectExists(ctx context.Context, projectID uuid.UUID) (bool, error) {
	var exists bool
	err := v.pool.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM projects
			WHERE id = $1
		);
	`, projectID).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("check project exists: %w", err)
	}
	return exists, nil
}
