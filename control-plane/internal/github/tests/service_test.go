package tests

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	authv1 "github.com/skxm03/kr0n-backend/control-plane/gen/auth/v1"
	"github.com/skxm03/kr0n-backend/control-plane/internal/github/client"
	"github.com/skxm03/kr0n-backend/control-plane/internal/github/service"
)

type mockAuthClient struct {
	tokenResp *authv1.GetGitHubInstallationTokenResponse
	err       error
	lastReq   *authv1.GetGitHubInstallationTokenRequest
}

func (m *mockAuthClient) GetGitHubInstallationToken(ctx context.Context, in *authv1.GetGitHubInstallationTokenRequest, opts ...grpc.CallOption) (*authv1.GetGitHubInstallationTokenResponse, error) {
	m.lastReq = in
	if m.err != nil {
		return nil, m.err
	}
	return m.tokenResp, nil
}

type mockGitHubClient struct {
	repos     []client.Repository
	branches  []client.Branch
	dirs      []string
	presets   map[string]string
	err       error
	lastToken string
}

func (m *mockGitHubClient) ListRepositories(ctx context.Context, token string) ([]client.Repository, error) {
	m.lastToken = token
	if m.err != nil {
		return nil, m.err
	}
	return m.repos, nil
}

func (m *mockGitHubClient) ListBranches(ctx context.Context, token string, owner, repo string) ([]client.Branch, error) {
	m.lastToken = token
	if m.err != nil {
		return nil, m.err
	}
	return m.branches, nil
}

func (m *mockGitHubClient) ListDirectories(ctx context.Context, token string, owner, repo, ref string) ([]string, error) {
	m.lastToken = token
	if m.err != nil {
		return nil, m.err
	}
	return m.dirs, nil
}

func (m *mockGitHubClient) ListDirectoriesWithPresets(ctx context.Context, token string, owner, repo, ref string) ([]string, map[string]string, error) {
	m.lastToken = token
	if m.err != nil {
		return nil, nil, m.err
	}
	if m.presets != nil {
		return m.dirs, m.presets, nil
	}
	presets := make(map[string]string)
	for _, d := range m.dirs {
		presets[d] = "auto"
	}
	return m.dirs, presets, nil
}

func TestService_ListRepositories_DelegatesTokenWithPassport(t *testing.T) {
	orgID := uuid.New().String()
	caller := &authv1.CallerPrincipal{
		UserId: uuid.New().String(),
		Kind:   "user",
	}

	authMock := &mockAuthClient{
		tokenResp: &authv1.GetGitHubInstallationTokenResponse{
			Token:          "minted-ghs-token",
			InstallationId: 9901,
		},
	}
	ghMock := &mockGitHubClient{
		repos: []client.Repository{
			{ID: 1, Name: "monorepo", FullName: "acme/monorepo"},
		},
	}

	svc := service.NewService(authMock, ghMock)
	ctx := context.Background()

	repos, err := svc.ListRepositories(ctx, caller, orgID, 9901)
	if err != nil {
		t.Fatalf("ListRepositories: %v", err)
	}
	if len(repos) != 1 || repos[0].Name != "monorepo" {
		t.Fatalf("unexpected repos: %+v", repos)
	}

	// Verify passport and orgID were passed to Auth Service
	if authMock.lastReq.GetOrgId() != orgID || authMock.lastReq.GetCaller().GetUserId() != caller.GetUserId() {
		t.Fatalf("auth client received incorrect params: %+v", authMock.lastReq)
	}
	// Verify token was passed to GitHub client
	if ghMock.lastToken != "minted-ghs-token" {
		t.Fatalf("expected token minted-ghs-token, got %s", ghMock.lastToken)
	}
}

func TestService_Validation_MaliciousInputs(t *testing.T) {
	svc := service.NewService(&mockAuthClient{}, &mockGitHubClient{})
	ctx := context.Background()
	caller := &authv1.CallerPrincipal{UserId: uuid.New().String()}
	orgID := uuid.New().String()

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

func TestService_AuthServiceErrorPropagation(t *testing.T) {
	authMock := &mockAuthClient{
		err: status.Error(codes.PermissionDenied, "user lacks service:read on org"),
	}
	svc := service.NewService(authMock, &mockGitHubClient{})

	_, err := svc.ListRepositories(context.Background(), &authv1.CallerPrincipal{}, uuid.New().String(), 1)
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("expected PermissionDenied, got %v", err)
	}
}
