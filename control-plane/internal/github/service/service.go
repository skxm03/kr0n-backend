package service

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/google/uuid"
	"google.golang.org/grpc"

	authv1 "github.com/skxm03/kr0n-backend/control-plane/gen/auth/v1"
	"github.com/skxm03/kr0n-backend/control-plane/internal/github/client"
)

var (
	ownerRegex = regexp.MustCompile(`^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,37}[a-zA-Z0-9])?$`)
	repoRegex  = regexp.MustCompile(`^[a-zA-Z0-9_.-]{1,100}$`)
)

// AuthServiceClient abstracts the Auth Service RPCs needed by GitHubService.
type AuthServiceClient interface {
	GetGitHubInstallationToken(ctx context.Context, in *authv1.GetGitHubInstallationTokenRequest, opts ...grpc.CallOption) (*authv1.GetGitHubInstallationTokenResponse, error)
}

// Service orchestrates caller authorization, token delegation from Auth Service, and GitHub API operations.
type Service struct {
	authClient AuthServiceClient
	ghClient   client.Client
}

// NewService creates a new GitHub service instance.
func NewService(authClient AuthServiceClient, ghClient client.Client) *Service {
	return &Service{
		authClient: authClient,
		ghClient:   ghClient,
	}
}

// ListRepositories retrieves all repositories accessible to the organization's GitHub installation.
func (s *Service) ListRepositories(ctx context.Context, caller *authv1.CallerPrincipal, orgID string, installationID int64) ([]client.Repository, error) {
	if _, err := uuid.Parse(strings.TrimSpace(orgID)); err != nil {
		return nil, fmt.Errorf("%w: invalid organization id", client.ErrInvalidInput)
	}

	tokResp, err := s.authClient.GetGitHubInstallationToken(ctx, &authv1.GetGitHubInstallationTokenRequest{
		Caller:         caller,
		OrgId:          orgID,
		InstallationId: installationID,
	})
	if err != nil {
		return nil, err
	}

	return s.ghClient.ListRepositories(ctx, tokResp.GetToken())
}

// ListBranches retrieves repository branches for owner/repo.
func (s *Service) ListBranches(ctx context.Context, caller *authv1.CallerPrincipal, orgID string, installationID int64, owner, repo string) ([]client.Branch, error) {
	if _, err := uuid.Parse(strings.TrimSpace(orgID)); err != nil {
		return nil, fmt.Errorf("%w: invalid organization id", client.ErrInvalidInput)
	}
	if err := validateOwnerRepo(owner, repo); err != nil {
		return nil, err
	}

	tokResp, err := s.authClient.GetGitHubInstallationToken(ctx, &authv1.GetGitHubInstallationTokenRequest{
		Caller:         caller,
		OrgId:          orgID,
		InstallationId: installationID,
	})
	if err != nil {
		return nil, err
	}

	return s.ghClient.ListBranches(ctx, tokResp.GetToken(), owner, repo)
}

// ListDirectories retrieves canonical directory paths for owner/repo at ref along with detected presets.
func (s *Service) ListDirectories(ctx context.Context, caller *authv1.CallerPrincipal, orgID string, installationID int64, owner, repo, ref string) ([]string, map[string]string, error) {
	if _, err := uuid.Parse(strings.TrimSpace(orgID)); err != nil {
		return nil, nil, fmt.Errorf("%w: invalid organization id", client.ErrInvalidInput)
	}
	if err := validateOwnerRepo(owner, repo); err != nil {
		return nil, nil, err
	}
	if err := validateRef(ref); err != nil {
		return nil, nil, err
	}

	tokResp, err := s.authClient.GetGitHubInstallationToken(ctx, &authv1.GetGitHubInstallationTokenRequest{
		Caller:         caller,
		OrgId:          orgID,
		InstallationId: installationID,
	})
	if err != nil {
		return nil, nil, err
	}

	if withPresets, ok := s.ghClient.(interface {
		ListDirectoriesWithPresets(ctx context.Context, token string, owner, repo, ref string) ([]string, map[string]string, error)
	}); ok {
		return withPresets.ListDirectoriesWithPresets(ctx, tokResp.GetToken(), owner, repo, ref)
	}

	dirs, err := s.ghClient.ListDirectories(ctx, tokResp.GetToken(), owner, repo, ref)
	return dirs, nil, err
}

func validateOwnerRepo(owner, repo string) error {
	o := strings.TrimSpace(owner)
	r := strings.TrimSpace(repo)
	if !ownerRegex.MatchString(o) {
		return fmt.Errorf("%w: invalid owner name %q", client.ErrInvalidInput, owner)
	}
	if !repoRegex.MatchString(r) || strings.Contains(r, "..") {
		return fmt.Errorf("%w: invalid repository name %q", client.ErrInvalidInput, repo)
	}
	return nil
}

func validateRef(ref string) error {
	r := strings.TrimSpace(ref)
	if r == "" {
		return nil // Defaults to HEAD
	}
	if strings.Contains(r, "..") || strings.ContainsAny(r, " \t\r\n~^:?*[\\]") {
		return fmt.Errorf("%w: invalid git ref %q", client.ErrInvalidInput, ref)
	}
	return nil
}
