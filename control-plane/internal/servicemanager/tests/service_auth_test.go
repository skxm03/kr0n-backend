package tests

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	authv1 "github.com/skxm03/kr0n-backend/control-plane/gen/auth/v1"
	servicemanagerv1 "github.com/skxm03/kr0n-backend/control-plane/gen/servicemanager/v1"
	"github.com/skxm03/kr0n-backend/control-plane/internal/servicemanager/domain"
	"github.com/skxm03/kr0n-backend/control-plane/internal/servicemanager/handlers"
	"github.com/skxm03/kr0n-backend/control-plane/internal/servicemanager/repository"
	"github.com/skxm03/kr0n-backend/control-plane/internal/servicemanager/service"
	"github.com/skxm03/kr0n-backend/control-plane/pkg/grpcauth"
)

type dummyAuthorizer struct{}

func (d dummyAuthorizer) CheckPermission(_ context.Context, _ domain.Principal, _ uuid.UUID, _ string) (bool, error) {
	return true, nil
}

type dummyInstVerifier struct{}

func (d dummyInstVerifier) VerifyActiveOrgInstallation(_ context.Context, _ uuid.UUID, _ int64) (bool, error) {
	return true, nil
}

type dummyProjectRepo struct{}

func (d dummyProjectRepo) CreateProject(_ context.Context, p *domain.Project) (*domain.Project, error) {
	return p, nil
}
func (d dummyProjectRepo) GetProject(_ context.Context, orgID, projectID uuid.UUID) (*domain.Project, error) {
	return &domain.Project{ID: projectID, OrganizationID: orgID, Name: "Test Project"}, nil
}
func (d dummyProjectRepo) ListProjects(_ context.Context, orgID uuid.UUID, limit, offset int) ([]domain.Project, error) {
	return []domain.Project{}, nil
}
func (d dummyProjectRepo) UpdateProject(_ context.Context, mut repository.UpdateProjectMutation) (*domain.Project, error) {
	return &domain.Project{}, nil
}
func (d dummyProjectRepo) UpdateBuildSettings(_ context.Context, orgID, projectID uuid.UUID, expectedRevision int64, bs domain.BuildSettings) (*domain.Project, error) {
	return &domain.Project{}, nil
}
func (d dummyProjectRepo) DeleteProject(_ context.Context, orgID, projectID uuid.UUID) error {
	return nil
}

func TestServiceManager_ServiceAuthentication_Enforcement(t *testing.T) {
	ctx := context.Background()
	orgID := uuid.New()
	ownerID := uuid.New()

	svc := service.NewProjectService(
		dummyProjectRepo{},
		service.WithAuthorizer(dummyAuthorizer{}),
		service.WithInstallationVerifier(dummyInstVerifier{}),
	)

	serviceAuthCfg := grpcauth.ServiceAuthConfig{
		Enabled:            true,
		RequireClientCert:  true,
		AllowedClientNames: []string{"kr0n-gateway"},
	}

	srv := handlers.NewServer(
		svc,
		handlers.WithServiceAuthConfig(serviceAuthCfg),
	)

	caller := &authv1.CallerPrincipal{UserId: ownerID.String(), Kind: "session"}

	// 1. Untrusted caller calling GetProject -> MUST return Unauthenticated
	_, err := srv.GetProject(ctx, &servicemanagerv1.GetProjectRequest{
		Caller:    caller,
		OrgId:     orgID.String(),
		ProjectId: uuid.New().String(),
	})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("expected Unauthenticated for untrusted GetProject call, got %v", err)
	}

	// 2. Untrusted caller calling ListProjects -> MUST return Unauthenticated
	_, err = srv.ListProjects(ctx, &servicemanagerv1.ListProjectsRequest{
		Caller: caller,
		OrgId:  orgID.String(),
	})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("expected Unauthenticated for untrusted ListProjects call, got %v", err)
	}

	// 3. Authenticated caller from trusted service (kr0n-gateway) -> passes service boundary
	trustedCtx := grpcauth.WithTrustedService(ctx, "kr0n-gateway")
	res, err := srv.GetProject(trustedCtx, &servicemanagerv1.GetProjectRequest{
		Caller:    caller,
		OrgId:     orgID.String(),
		ProjectId: uuid.New().String(),
	})
	if err != nil {
		t.Fatalf("expected trusted caller to succeed, got %v", err)
	}
	if res.GetProject().GetName() != "Test Project" {
		t.Fatalf("expected project name 'Test Project', got %q", res.GetProject().GetName())
	}
}
