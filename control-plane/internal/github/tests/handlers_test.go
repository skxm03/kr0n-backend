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
	pkgAudit "github.com/skxm03/kr0n-backend/control-plane/pkg/audit"
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
			"/apps/api": "golang",
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
	if resp.GetCurrentDirectory() == nil || resp.GetCurrentDirectory().GetPath() != "/" {
		t.Fatalf("expected current_directory at '/', got %+v", resp.GetCurrentDirectory())
	}
	if len(resp.GetChildren()) != 2 {
		t.Fatalf("expected 2 child directories, got %d", len(resp.GetChildren()))
	}
	if resp.GetChildren()[0].GetPath() != "/apps/api" || resp.GetChildren()[0].GetDetectedPreset() != "golang" {
		t.Fatalf("unexpected child 0: %+v", resp.GetChildren()[0])
	}
	if resp.GetChildren()[1].GetPath() != "/apps/web" || resp.GetChildren()[1].GetDetectedPreset() != "nextjs" {
		t.Fatalf("unexpected child 1: %+v", resp.GetChildren()[1])
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

type testAuditEmitter struct {
	events []pkgAudit.Event
}

func (e *testAuditEmitter) Emit(_ context.Context, ev pkgAudit.Event) error {
	e.events = append(e.events, ev)
	return nil
}

func (e *testAuditEmitter) EmitSync(ctx context.Context, ev pkgAudit.Event) error {
	return e.Emit(ctx, ev)
}

func (e *testAuditEmitter) Close() error {
	return nil
}

func TestHandlers_InstallationAuditEvents(t *testing.T) {
	orgID := uuid.New().String()
	userID := uuid.New().String()
	caller := &authv1.CallerPrincipal{
		UserId: userID,
		Kind:   "user",
	}

	ghApp := newMockGitHubApp("scoped-token")
	repo := newMockInstallationRepo()
	authorizer := &mockAuthorizer{allowed: true}

	svc := service.NewService(
		service.WithAuthorizer(authorizer),
		service.WithGitHubApp(ghApp),
		service.WithInstallationRepository(repo),
	)

	emitter := &testAuditEmitter{}
	srv := handlers.NewServer(svc, handlers.WithAuditEmitter(emitter))
	ctx := context.Background()

	// 1. Complete installation should emit ActionGitHubInstallationConnected
	compResp, err := srv.CompleteGitHubInstallation(ctx, &githubv1.CompleteGitHubInstallationRequest{
		Caller:         caller,
		OrgId:          orgID,
		InstallationId: 9988,
		State:          "valid-state",
	})
	if err != nil {
		t.Fatalf("CompleteGitHubInstallation: %v", err)
	}
	if compResp.GetInstallation().GetInstallationId() != 9988 {
		t.Fatalf("unexpected installation id: %d", compResp.GetInstallation().GetInstallationId())
	}

	if len(emitter.events) != 1 {
		t.Fatalf("expected 1 audit event after complete, got %d", len(emitter.events))
	}
	ev0 := emitter.events[0]
	if ev0.Action != pkgAudit.ActionGitHubInstallationConnected.String() {
		t.Errorf("expected action %q, got %q", pkgAudit.ActionGitHubInstallationConnected.String(), ev0.Action)
	}
	if ev0.Target.Type != pkgAudit.TargetTypeGitHubInstallation {
		t.Errorf("expected target type %q, got %q", pkgAudit.TargetTypeGitHubInstallation, ev0.Target.Type)
	}
	if ev0.Target.ID != "9988" {
		t.Errorf("expected target id 9988, got %q", ev0.Target.ID)
	}
	if ev0.OrganizationID == nil || ev0.OrganizationID.String() != orgID {
		t.Errorf("expected organization id %s, got %v", orgID, ev0.OrganizationID)
	}
	if ev0.Actor.UserID == nil || ev0.Actor.UserID.String() != userID {
		t.Errorf("expected actor user id %s, got %v", userID, ev0.Actor.UserID)
	}

	// 2. Disconnect installation should emit ActionGitHubInstallationDisconnected
	_, err = srv.DisconnectGitHubInstallation(ctx, &githubv1.DisconnectGitHubInstallationRequest{
		Caller:         caller,
		OrgId:          orgID,
		InstallationId: 9988,
	})
	if err != nil {
		t.Fatalf("DisconnectGitHubInstallation: %v", err)
	}

	if len(emitter.events) != 2 {
		t.Fatalf("expected 2 audit events after disconnect, got %d", len(emitter.events))
	}
	ev1 := emitter.events[1]
	if ev1.Action != pkgAudit.ActionGitHubInstallationDisconnected.String() {
		t.Errorf("expected action %q, got %q", pkgAudit.ActionGitHubInstallationDisconnected.String(), ev1.Action)
	}
	if ev1.Target.Type != pkgAudit.TargetTypeGitHubInstallation {
		t.Errorf("expected target type %q, got %q", pkgAudit.TargetTypeGitHubInstallation, ev1.Target.Type)
	}
	if ev1.Target.ID != "9988" {
		t.Errorf("expected target id 9988, got %q", ev1.Target.ID)
	}
}
