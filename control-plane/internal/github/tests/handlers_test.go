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
	"github.com/skxm03/kr0n-backend/control-plane/internal/github/handlers"
	"github.com/skxm03/kr0n-backend/control-plane/internal/github/service"
)

func TestHandlers_ListRepositories_EndToEnd(t *testing.T) {
	orgID := uuid.New().String()
	caller := &authv1.CallerPrincipal{
		UserId: uuid.New().String(),
		Kind:   "user",
	}

	authMock := &mockAuthClient{
		tokenResp: &authv1.GetGitHubInstallationTokenResponse{
			Token:          "scoped-ghs-token",
			InstallationId: 1234,
		},
	}
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

	srv := handlers.NewServer(service.NewService(authMock, ghMock))
	ctx := context.Background()

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
	repo := resp.GetRepositories()[0]
	if repo.GetUpdatedAt() != "2026-11-20T10:00:00Z" || repo.GetPushedAt() != "2026-11-20T10:30:00Z" {
		t.Fatalf("unexpected repo timestamps: %+v", repo)
	}
	if repo.GetDescription() != "Frontend application" || repo.GetLanguage() != "TypeScript" {
		t.Fatalf("unexpected repo description/language: %+v", repo)
	}
}

func TestHandlers_ListBranches_EndToEnd(t *testing.T) {
	orgID := uuid.New().String()
	caller := &authv1.CallerPrincipal{UserId: uuid.New().String()}

	authMock := &mockAuthClient{
		tokenResp: &authv1.GetGitHubInstallationTokenResponse{
			Token:          "scoped-ghs-token",
			InstallationId: 1234,
		},
	}
	ghMock := &mockGitHubClient{
		branches: []client.Branch{
			{Name: "main", CommitSHA: "sha123", Protected: true},
		},
	}

	srv := handlers.NewServer(service.NewService(authMock, ghMock))
	ctx := context.Background()

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
	caller := &authv1.CallerPrincipal{UserId: uuid.New().String()}

	authMock := &mockAuthClient{
		tokenResp: &authv1.GetGitHubInstallationTokenResponse{
			Token:          "scoped-ghs-token",
			InstallationId: 1234,
		},
	}
	ghMock := &mockGitHubClient{
		dirs: []string{"/", "/apps/api", "/apps/web"},
		presets: map[string]string{
			"/apps/api": "go",
			"/apps/web": "nextjs",
		},
	}

	srv := handlers.NewServer(service.NewService(authMock, ghMock))
	ctx := context.Background()

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
	if len(resp.GetEntries()) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(resp.GetEntries()))
	}
	if resp.GetEntries()[0].GetPath() != "/" || resp.GetEntries()[0].GetParentPath() != "" {
		t.Fatalf("unexpected root entry: %+v", resp.GetEntries()[0])
	}
	if resp.GetEntries()[1].GetPath() != "/apps/api" || resp.GetEntries()[1].GetName() != "api" || resp.GetEntries()[1].GetParentPath() != "/apps" || resp.GetEntries()[1].GetDetectedPreset() != "go" {
		t.Fatalf("unexpected entry 1: %+v", resp.GetEntries()[1])
	}
	if resp.GetEntries()[2].GetDetectedPreset() != "nextjs" {
		t.Fatalf("unexpected entry 2: %+v", resp.GetEntries()[2])
	}
	if resp.GetRoot() == nil || resp.GetRoot().GetPath() != "/" {
		t.Fatalf("unexpected root node: %+v", resp.GetRoot())
	}
}

func TestHandlers_NilRequestAndValidationErrors(t *testing.T) {
	srv := handlers.NewServer(service.NewService(&mockAuthClient{}, &mockGitHubClient{}))
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
