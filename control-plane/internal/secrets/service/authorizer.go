package service

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	authv1 "github.com/skxm03/kr0n-backend/control-plane/gen/auth/v1"
	servicemanagerv1 "github.com/skxm03/kr0n-backend/control-plane/gen/servicemanager/v1"
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

// ProjectVerifier verifies that a project exists and is owned by orgID.
type ProjectVerifier interface {
	VerifyProject(ctx context.Context, orgID, projectID uuid.UUID) (bool, error)
	ProjectExists(ctx context.Context, projectID uuid.UUID) (bool, error)
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
