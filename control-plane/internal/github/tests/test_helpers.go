package tests

import (
	"context"
	"sync"
	"time"

	"github.com/google/uuid"

	authv1 "github.com/skxm03/kr0n-backend/control-plane/gen/auth/v1"
	"github.com/skxm03/kr0n-backend/control-plane/internal/github/client"
	"github.com/skxm03/kr0n-backend/control-plane/internal/github/domain"
	"github.com/skxm03/kr0n-backend/control-plane/internal/github/provider"
)

type mockAuthorizer struct {
	allowed bool
	err     error
}

func (m *mockAuthorizer) CheckPermission(ctx context.Context, caller *authv1.CallerPrincipal, orgID, permission string) (bool, error) {
	if m.err != nil {
		return false, m.err
	}
	return m.allowed, nil
}

type mockGitHubApp struct {
	mu           sync.Mutex
	token        string
	tokenErr     error
	instMetadata *provider.GitHubAppInstallation
	instErr      error
	tokens       map[int64]string
}

func newMockGitHubApp(token string) *mockGitHubApp {
	return &mockGitHubApp{
		token:  token,
		tokens: make(map[int64]string),
	}
}

func (m *mockGitHubApp) Configured() bool {
	return true
}

func (m *mockGitHubApp) StartInstallation(orgID, userID uuid.UUID) (string, string, error) {
	return "https://github.com/apps/test-app/installations/new?state=valid-state", "valid-state", nil
}

func (m *mockGitHubApp) VerifyState(state string, expectedOrgID, expectedUserID uuid.UUID) error {
	if state == "invalid-state" {
		return provider.ErrInvalidInstallationState
	}
	return nil
}

func (m *mockGitHubApp) GetInstallationToken(ctx context.Context, installationID int64) (string, time.Time, error) {
	if m.tokenErr != nil {
		return "", time.Time{}, m.tokenErr
	}
	tok := m.token
	if tok == "" {
		tok = "mock-ghs-token"
	}
	return tok, time.Now().Add(time.Hour), nil
}

func (m *mockGitHubApp) InvalidateInstallationToken(installationID int64) {
	m.mu.Lock()
	delete(m.tokens, installationID)
	m.mu.Unlock()
}

func (m *mockGitHubApp) GetInstallation(ctx context.Context, installationID int64) (*provider.GitHubAppInstallation, error) {
	if m.instErr != nil {
		return nil, m.instErr
	}
	if m.instMetadata != nil {
		return m.instMetadata, nil
	}
	return &provider.GitHubAppInstallation{
		InstallationID:      installationID,
		AccountLogin:        "test-org",
		AccountType:         "Organization",
		RepositorySelection: "all",
		Status:              "active",
	}, nil
}

type mockInstallationRepo struct {
	mu            sync.Mutex
	installations map[int64]*domain.GitHubInstallation
}

func newMockInstallationRepo() *mockInstallationRepo {
	return &mockInstallationRepo{
		installations: make(map[int64]*domain.GitHubInstallation),
	}
}

func (m *mockInstallationRepo) UpsertGitHubInstallation(ctx context.Context, inst *domain.GitHubInstallation) (*domain.GitHubInstallation, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.installations[inst.InstallationID] = inst
	return inst, nil
}

func (m *mockInstallationRepo) ListGitHubInstallations(ctx context.Context, orgID uuid.UUID) ([]domain.GitHubInstallation, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []domain.GitHubInstallation
	for _, inst := range m.installations {
		if inst.OrganizationID == orgID {
			out = append(out, *inst)
		}
	}
	return out, nil
}

func (m *mockInstallationRepo) DeleteGitHubInstallation(ctx context.Context, orgID uuid.UUID, installationID int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.installations[installationID]; !ok {
		return domain.ErrInstallationNotFound
	}
	delete(m.installations, installationID)
	return nil
}

func (m *mockInstallationRepo) UpdateGitHubInstallationStatus(ctx context.Context, installationID int64, status string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	inst, ok := m.installations[installationID]
	if !ok {
		return domain.ErrInstallationNotFound
	}
	inst.Status = status
	return nil
}

func (m *mockInstallationRepo) GetGitHubInstallationByInstallationID(ctx context.Context, installationID int64) (*domain.GitHubInstallation, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	inst, ok := m.installations[installationID]
	if !ok {
		return nil, domain.ErrInstallationNotFound
	}
	return inst, nil
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
