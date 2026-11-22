package tests

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	authv1 "github.com/skxm03/kr0n-backend/control-plane/gen/auth/v1"
	"github.com/skxm03/kr0n-backend/control-plane/internal/github/client"
	"github.com/skxm03/kr0n-backend/control-plane/internal/github/domain"
	"github.com/skxm03/kr0n-backend/control-plane/internal/github/service"
)

func TestService_ListRepositories_DelegatesTokenWithPassport(t *testing.T) {
	orgID := uuid.New().String()
	parsedOrgID, _ := uuid.Parse(orgID)
	caller := &authv1.CallerPrincipal{
		UserId: uuid.New().String(),
		Kind:   "user",
	}

	ghApp := newMockGitHubApp("minted-ghs-token")
	repo := newMockInstallationRepo()
	ctx := context.Background()
	_, _ = repo.UpsertGitHubInstallation(ctx, &domain.GitHubInstallation{
		OrganizationID: parsedOrgID,
		InstallationID: 9901,
		Status:         "active",
	})

	ghMock := &mockGitHubClient{
		repos: []client.Repository{
			{ID: 1, Name: "monorepo", FullName: "acme/monorepo"},
		},
	}

	svc := service.NewService(
		service.WithGitHubApp(ghApp),
		service.WithInstallationRepository(repo),
		service.WithGitHubClient(ghMock),
	)

	repos, err := svc.ListRepositories(ctx, caller, orgID, 9901)
	if err != nil {
		t.Fatalf("ListRepositories: %v", err)
	}
	if len(repos) != 1 || repos[0].Name != "monorepo" {
		t.Fatalf("unexpected repos: %+v", repos)
	}

	// Verify token was passed to GitHub client
	if ghMock.lastToken != "minted-ghs-token" {
		t.Fatalf("expected token minted-ghs-token, got %s", ghMock.lastToken)
	}
}

func TestService_Validation_MaliciousInputs(t *testing.T) {
	ghApp := newMockGitHubApp("test-tok")
	repo := newMockInstallationRepo()
	svc := service.NewService(
		service.WithGitHubApp(ghApp),
		service.WithInstallationRepository(repo),
		service.WithGitHubClient(&mockGitHubClient{}),
	)
	ctx := context.Background()
	caller := &authv1.CallerPrincipal{UserId: uuid.New().String()}
	orgID := uuid.New().String()
	parsedOrgID, _ := uuid.Parse(orgID)
	_, _ = repo.UpsertGitHubInstallation(ctx, &domain.GitHubInstallation{
		OrganizationID: parsedOrgID,
		InstallationID: 1,
		Status:         "active",
	})

	// Invalid Org ID
	if _, err := svc.ListRepositories(ctx, caller, "not-a-uuid", 1); !errors.Is(err, client.ErrInvalidInput) {
		t.Fatalf("expected ErrInvalidInput for bad orgID, got %v", err)
	}

	// Path traversal in owner
	if _, err := svc.ListBranches(ctx, caller, orgID, 1, "../evil", "repo"); !errors.Is(err, client.ErrInvalidInput) {
		t.Fatalf("expected ErrInvalidInput for traversal owner, got %v", err)
	}

	// Path traversal in repo
	if _, err := svc.ListBranches(ctx, caller, orgID, 1, "acme", "repo/../../etc"); !errors.Is(err, client.ErrInvalidInput) {
		t.Fatalf("expected ErrInvalidInput for traversal repo, got %v", err)
	}

	// Invalid ref
	if _, _, err := svc.ListDirectories(ctx, caller, orgID, 1, "acme", "repo", "main..feat"); !errors.Is(err, client.ErrInvalidInput) {
		t.Fatalf("expected ErrInvalidInput for invalid ref, got %v", err)
	}
}

func TestService_AuthorizerErrorPropagation(t *testing.T) {
	authMock := &mockAuthorizer{
		err: status.Error(codes.PermissionDenied, "user lacks service:read on org"),
	}
	svc := service.NewService(
		service.WithAuthorizer(authMock),
		service.WithGitHubApp(newMockGitHubApp("tok")),
		service.WithGitHubClient(&mockGitHubClient{}),
	)

	_, err := svc.ListRepositories(context.Background(), &authv1.CallerPrincipal{}, uuid.New().String(), 1)
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("expected PermissionDenied, got %v", err)
	}
}
