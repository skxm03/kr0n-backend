package tests

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	authv1 "github.com/skxm03/kr0n-backend/control-plane/gen/auth/v1"
	githubv1 "github.com/skxm03/kr0n-backend/control-plane/gen/github/v1"
	"github.com/skxm03/kr0n-backend/control-plane/internal/github/client"
	"github.com/skxm03/kr0n-backend/control-plane/internal/github/domain"
	"github.com/skxm03/kr0n-backend/control-plane/internal/github/handlers"
	"github.com/skxm03/kr0n-backend/control-plane/internal/github/service"
)

func TestHandlers_ListRepositories_EndToEnd(t *testing.T) {
	orgID := uuid.New().String()
	parsedOrgID, _ := uuid.Parse(orgID)
	caller := &authv1.CallerPrincipal{
		UserId: uuid.New().String(),
		Kind:   "user",
	}

	ghApp := newMockGitHubApp("scoped-ghs-token")
	repo := newMockInstallationRepo()
	ctx := context.Background()
	_, _ = repo.UpsertGitHubInstallation(ctx, &domain.GitHubInstallation{
		OrganizationID: parsedOrgID,
		InstallationID: 1234,
		Status:         "active",
	})

	ghMock := &mockGitHubClient{
		repos: []client.Repository{
			{
				ID:            555,
				Owner:         "acme",
				Name:          "kr0n-frontend",
				FullName:      "acme/kr0n-frontend",
				Private:       false,
				DefaultBranch: "main",
				HTMLURL:       "https://github.com/acme/kr0n-frontend",
				UpdatedAt:     "2026-11-20T10:00:00Z",
				PushedAt:      "2026-11-20T10:30:00Z",
				Description:   "Frontend application",
				Language:      "TypeScript",
			},
		},
	}

	svc := service.NewService(
		service.WithGitHubApp(ghApp),
		service.WithInstallationRepository(repo),
		service.WithGitHubClient(ghMock),
	)
	srv := handlers.NewServer(svc)

	resp, err := srv.ListRepositories(ctx, &githubv1.ListRepositoriesRequest{
		Caller:         caller,
		OrgId:          orgID,
		InstallationId: 1234,
	})
	if err != nil {
		t.Fatalf("ListRepositories: %v", err)
	}
	if len(resp.GetRepositories()) != 1 || resp.GetRepositories()[0].GetName() != "kr0n-frontend" {
		t.Fatalf("unexpected repositories: %+v", resp)
	}
	r := resp.GetRepositories()[0]
	if r.GetUpdatedAt() != "2026-11-20T10:00:00Z" || r.GetPushedAt() != "2026-11-20T10:30:00Z" {
		t.Fatalf("unexpected repo timestamps: %+v", r)
	}
	if r.GetDescription() != "Frontend application" || r.GetLanguage() != "TypeScript" {
		t.Fatalf("unexpected repo description/language: %+v", r)
	}
}

func TestHandlers_ListBranches_EndToEnd(t *testing.T) {
	orgID := uuid.New().String()
	parsedOrgID, _ := uuid.Parse(orgID)
	caller := &authv1.CallerPrincipal{UserId: uuid.New().String()}

	ghApp := newMockGitHubApp("scoped-ghs-token")
	repo := newMockInstallationRepo()
	ctx := context.Background()
	_, _ = repo.UpsertGitHubInstallation(ctx, &domain.GitHubInstallation{
		OrganizationID: parsedOrgID,
		InstallationID: 1234,
		Status:         "active",
	})

	ghMock := &mockGitHubClient{
		branches: []client.Branch{
			{Name: "main", CommitSHA: "sha123", Protected: true},
		},
	}

	svc := service.NewService(
		service.WithGitHubApp(ghApp),
		service.WithInstallationRepository(repo),
		service.WithGitHubClient(ghMock),
	)
	srv := handlers.NewServer(svc)

	resp, err := srv.ListBranches(ctx, &githubv1.ListBranchesRequest{
		Caller:         caller,
		OrgId:          orgID,
		InstallationId: 1234,
		Owner:          "acme",
		Repo:           "frontend",
	})
	if err != nil {
		t.Fatalf("ListBranches: %v", err)
	}
	if len(resp.GetBranches()) != 1 || resp.GetBranches()[0].GetName() != "main" {
		t.Fatalf("unexpected branches: %+v", resp)
	}
}

func TestHandlers_ListDirectories_EndToEnd(t *testing.T) {
	orgID := uuid.New().String()
	parsedOrgID, _ := uuid.Parse(orgID)
	caller := &authv1.CallerPrincipal{UserId: uuid.New().String()}

	ghApp := newMockGitHubApp("scoped-ghs-token")
	repo := newMockInstallationRepo()
	ctx := context.Background()
	_, _ = repo.UpsertGitHubInstallation(ctx, &domain.GitHubInstallation{
		OrganizationID: parsedOrgID,
		InstallationID: 1234,
		Status:         "active",
	})

	ghMock := &mockGitHubClient{
		dirs: []string{"/", "/apps/api", "/apps/web"},
		presets: map[string]string{
			"/apps/api": "go",
			"/apps/web": "nextjs",
		},
	}

	svc := service.NewService(
		service.WithGitHubApp(ghApp),
		service.WithInstallationRepository(repo),
		service.WithGitHubClient(ghMock),
	)
	srv := handlers.NewServer(svc)

	resp, err := srv.ListDirectories(ctx, &githubv1.ListDirectoriesRequest{
		Caller:         caller,
		OrgId:          orgID,
		InstallationId: 1234,
		Owner:          "acme",
		Repo:           "frontend",
		Ref:            "main",
	})
	if err != nil {
		t.Fatalf("ListDirectories: %v", err)
	}
	if len(resp.GetDirectories()) != 3 || resp.GetDirectories()[0] != "/" {
		t.Fatalf("unexpected directories: %+v", resp)
	}
	if len(resp.GetEntries()) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(resp.GetEntries()))
	}
	if resp.GetEntries()[0].GetPath() != "/apps/api" || resp.GetEntries()[0].GetName() != "api" || resp.GetEntries()[0].GetParentPath() != "/apps" || resp.GetEntries()[0].GetDetectedPreset() != "go" {
		t.Fatalf("unexpected entry 0: %+v", resp.GetEntries()[0])
	}
	if resp.GetEntries()[1].GetDetectedPreset() != "nextjs" {
		t.Fatalf("unexpected entry 1: %+v", resp.GetEntries()[1])
	}
	if resp.GetRoot() == nil || resp.GetRoot().GetPath() != "/" {
		t.Fatalf("unexpected root node: %+v", resp.GetRoot())
	}
}

func TestHandlers_NilRequestAndValidationErrors(t *testing.T) {
	svc := service.NewService(
		service.WithGitHubApp(newMockGitHubApp("tok")),
		service.WithInstallationRepository(newMockInstallationRepo()),
		service.WithGitHubClient(&mockGitHubClient{}),
	)
	srv := handlers.NewServer(svc)
	ctx := context.Background()

	if _, err := srv.ListRepositories(ctx, nil); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("expected InvalidArgument for nil request, got %v", err)
	}

	if _, err := srv.ListBranches(ctx, nil); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("expected InvalidArgument for nil request, got %v", err)
	}

	if _, err := srv.ListDirectories(ctx, nil); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("expected InvalidArgument for nil request, got %v", err)
	}

	// Invalid org ID
	_, err := srv.ListRepositories(ctx, &githubv1.ListRepositoriesRequest{
		OrgId: "invalid-uuid",
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("expected InvalidArgument for bad uuid, got %v", err)
	}
}
