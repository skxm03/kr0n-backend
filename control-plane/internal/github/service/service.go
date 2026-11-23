package service

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"

	authv1 "github.com/skxm03/kr0n-backend/control-plane/gen/auth/v1"
	"github.com/skxm03/kr0n-backend/control-plane/internal/github/client"
	"github.com/skxm03/kr0n-backend/control-plane/internal/github/domain"
	"github.com/skxm03/kr0n-backend/control-plane/internal/github/provider"
	"github.com/skxm03/kr0n-backend/control-plane/internal/github/repository"
	"github.com/skxm03/kr0n-backend/control-plane/internal/github/webhook"
)

var (
	ownerRegex = regexp.MustCompile(`^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,37}[a-zA-Z0-9])?$`)
	repoRegex  = regexp.MustCompile(`^[a-zA-Z0-9_.-]{1,100}$`)

	// ErrPermissionDenied indicates caller is not authorized for the requested operation.
	ErrPermissionDenied = errors.New("permission denied")
)

// Authorizer checks if caller principal holds the required permission on orgID.
type Authorizer interface {
	CheckPermission(ctx context.Context, caller *authv1.CallerPrincipal, orgID string, permission string) (bool, error)
}

// GitHubAppClient defines operations provided by GitHubAppProvider.
type GitHubAppClient interface {
	Configured() bool
	StartInstallation(orgID, userID uuid.UUID) (installURL, state string, err error)
	VerifyState(state string, expectedOrgID, expectedUserID uuid.UUID) error
	GetInstallationToken(ctx context.Context, installationID int64) (string, time.Time, error)
	InvalidateInstallationToken(installationID int64)
	GetInstallation(ctx context.Context, installationID int64) (*provider.GitHubAppInstallation, error)
}

// Service orchestrates caller authorization, installation lifecycle, token generation, and GitHub API operations.
type Service struct {
	authorizer     Authorizer
	ghApp          GitHubAppClient
	instRepo       repository.InstallationRepository
	ghClient       client.Client
	webhookHandler *webhook.WebhookHandler
}

// Option configures Service dependencies.
type Option func(*Service)

// WithAuthorizer sets the Authorizer.
func WithAuthorizer(a Authorizer) Option {
	return func(s *Service) {
		s.authorizer = a
	}
}

// WithGitHubApp sets the GitHubAppClient.
func WithGitHubApp(app GitHubAppClient) Option {
	return func(s *Service) {
		s.ghApp = app
	}
}

// WithInstallationRepository sets the InstallationRepository.
func WithInstallationRepository(repo repository.InstallationRepository) Option {
	return func(s *Service) {
		s.instRepo = repo
	}
}

// WithWebhookHandler sets the WebhookHandler.
func WithWebhookHandler(wh *webhook.WebhookHandler) Option {
	return func(s *Service) {
		s.webhookHandler = wh
	}
}

// WithGitHubClient sets the GitHub REST client.
func WithGitHubClient(c client.Client) Option {
	return func(s *Service) {
		s.ghClient = c
	}
}

// NewService creates a new GitHub service instance with options.
func NewService(opts ...Option) *Service {
	s := &Service{}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

func (s *Service) require(ctx context.Context, caller *authv1.CallerPrincipal, orgID, permission string) error {
	if s.authorizer == nil {
		return nil
	}
	allowed, err := s.authorizer.CheckPermission(ctx, caller, orgID, permission)
	if err != nil {
		return err
	}
	if !allowed {
		return ErrPermissionDenied
	}
	return nil
}

// StartGitHubInstallation generates a signed installation state token and GitHub App installation URL.
func (s *Service) StartGitHubInstallation(ctx context.Context, caller *authv1.CallerPrincipal, orgID string) (installURL, state string, err error) {
	parsedOrgID, err := uuid.Parse(strings.TrimSpace(orgID))
	if err != nil {
		return "", "", fmt.Errorf("%w: invalid organization id", client.ErrInvalidInput)
	}
	if err := s.require(ctx, caller, orgID, "org:update"); err != nil {
		return "", "", err
	}
	if s.ghApp == nil || !s.ghApp.Configured() {
		return "", "", provider.ErrGitHubAppNotConfigured
	}
	var userID uuid.UUID
	if caller != nil && caller.GetUserId() != "" {
		userID, _ = uuid.Parse(caller.GetUserId())
	}
	if userID == uuid.Nil {
		userID = uuid.New()
	}
	return s.ghApp.StartInstallation(parsedOrgID, userID)
}

// CompleteGitHubInstallation verifies state token, fetches installation metadata, and links it to the org.
func (s *Service) CompleteGitHubInstallation(ctx context.Context, caller *authv1.CallerPrincipal, orgID string, installationID int64, state string) (*domain.GitHubInstallation, error) {
	parsedOrgID, err := uuid.Parse(strings.TrimSpace(orgID))
	if err != nil {
		return nil, fmt.Errorf("%w: invalid organization id", client.ErrInvalidInput)
	}
	if installationID <= 0 {
		return nil, fmt.Errorf("%w: invalid installation id", client.ErrInvalidInput)
	}
	if err := s.require(ctx, caller, orgID, "org:update"); err != nil {
		return nil, err
	}
	if s.ghApp == nil || !s.ghApp.Configured() {
		return nil, provider.ErrGitHubAppNotConfigured
	}

	var userID uuid.UUID
	if caller != nil && caller.GetUserId() != "" {
		userID, _ = uuid.Parse(caller.GetUserId())
	}
	if userID != uuid.Nil {
		if err := s.ghApp.VerifyState(state, parsedOrgID, userID); err != nil {
			return nil, err
		}
	}

	meta, err := s.ghApp.GetInstallation(ctx, installationID)
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	inst := &domain.GitHubInstallation{
		ID:                  uuid.New(),
		OrganizationID:      parsedOrgID,
		InstallationID:      meta.InstallationID,
		AccountLogin:        meta.AccountLogin,
		AccountType:         meta.AccountType,
		RepositorySelection: meta.RepositorySelection,
		Status:              meta.Status,
		CreatedByUserID:     userID,
		CreatedAt:           now,
		UpdatedAt:           now,
	}

	if s.instRepo == nil {
		return inst, nil
	}
	return s.instRepo.UpsertGitHubInstallation(ctx, inst)
}

// ListGitHubInstallations lists GitHub installations linked to orgID.
func (s *Service) ListGitHubInstallations(ctx context.Context, caller *authv1.CallerPrincipal, orgID string) ([]domain.GitHubInstallation, error) {
	parsedOrgID, err := uuid.Parse(strings.TrimSpace(orgID))
	if err != nil {
		return nil, fmt.Errorf("%w: invalid organization id", client.ErrInvalidInput)
	}
	if err := s.require(ctx, caller, orgID, "service:read"); err != nil {
		if err2 := s.require(ctx, caller, orgID, "org:read"); err2 != nil {
			return nil, err
		}
	}
	if s.instRepo == nil {
		return nil, nil
	}
	return s.instRepo.ListGitHubInstallations(ctx, parsedOrgID)
}

// DisconnectGitHubInstallation unlinks a GitHub installation from orgID.
func (s *Service) DisconnectGitHubInstallation(ctx context.Context, caller *authv1.CallerPrincipal, orgID string, installationID int64) error {
	parsedOrgID, err := uuid.Parse(strings.TrimSpace(orgID))
	if err != nil {
		return fmt.Errorf("%w: invalid organization id", client.ErrInvalidInput)
	}
	if installationID <= 0 {
		return fmt.Errorf("%w: invalid installation id", client.ErrInvalidInput)
	}
	if err := s.require(ctx, caller, orgID, "org:update"); err != nil {
		return err
	}
	if s.instRepo != nil {
		if err := s.instRepo.DeleteGitHubInstallation(ctx, parsedOrgID, installationID); err != nil {
			return err
		}
	}
	if s.ghApp != nil {
		s.ghApp.InvalidateInstallationToken(installationID)
	}
	return nil
}

// GetInstallationToken resolves the installation and mints an ephemeral installation access token.
func (s *Service) GetInstallationToken(ctx context.Context, caller *authv1.CallerPrincipal, orgID string, installationID int64) (string, int64, time.Time, error) {
	parsedOrgID, err := uuid.Parse(strings.TrimSpace(orgID))
	if err != nil {
		return "", 0, time.Time{}, fmt.Errorf("%w: invalid organization id", client.ErrInvalidInput)
	}
	if err := s.require(ctx, caller, orgID, "service:read"); err != nil {
		if err2 := s.require(ctx, caller, orgID, "org:read"); err2 != nil {
			return "", 0, time.Time{}, err
		}
	}
	if s.ghApp == nil || !s.ghApp.Configured() {
		return "", 0, time.Time{}, provider.ErrGitHubAppNotConfigured
	}

	instID := installationID
	if instID <= 0 {
		if s.instRepo == nil {
			return "", 0, time.Time{}, domain.ErrInstallationNotFound
		}
		installations, err := s.instRepo.ListGitHubInstallations(ctx, parsedOrgID)
		if err != nil {
			return "", 0, time.Time{}, err
		}
		for _, inst := range installations {
			if strings.EqualFold(inst.Status, "active") {
				instID = inst.InstallationID
				break
			}
		}
		if instID <= 0 {
			return "", 0, time.Time{}, domain.ErrInstallationNotFound
		}
	} else if s.instRepo != nil {
		inst, err := s.instRepo.GetGitHubInstallationByInstallationID(ctx, instID)
		if err != nil {
			return "", 0, time.Time{}, err
		}
		if inst.OrganizationID != parsedOrgID {
			return "", 0, time.Time{}, domain.ErrInstallationNotFound
		}
		if !strings.EqualFold(inst.Status, "active") {
			return "", 0, time.Time{}, domain.ErrInstallationNotFound
		}
	}

	tok, exp, err := s.ghApp.GetInstallationToken(ctx, instID)
	if err != nil {
		if errors.Is(err, domain.ErrInstallationNotFound) || errors.Is(err, provider.ErrInstallationNotFound) {
			if s.instRepo != nil {
				_ = s.instRepo.DeleteGitHubInstallation(ctx, parsedOrgID, instID)
			}
			s.ghApp.InvalidateInstallationToken(instID)
			return "", 0, time.Time{}, domain.ErrInstallationNotFound
		}
		return "", 0, time.Time{}, err
	}
	return tok, instID, exp, nil
}

// HandleGitHubWebhook processes raw GitHub App webhook deliveries.
func (s *Service) HandleGitHubWebhook(ctx context.Context, payload []byte, sigHeader, eventType, deliveryID string) (string, error) {
	if s.webhookHandler == nil {
		return "received", nil
	}
	statusCode, respBytes, err := s.webhookHandler.Process(ctx, eventType, deliveryID, sigHeader, payload)
	if err != nil {
		return string(respBytes), err
	}
	if statusCode != http.StatusOK {
		return string(respBytes), fmt.Errorf("webhook processing status %d", statusCode)
	}
	return "received", nil
}

// UpdateGitHubInstallationStatus updates installation lifecycle status and invalidates cached token if non-active.
func (s *Service) UpdateGitHubInstallationStatus(ctx context.Context, installationID int64, status string) (*domain.GitHubInstallation, error) {
	if installationID <= 0 {
		return nil, domain.ErrInstallationNotFound
	}
	status = strings.ToLower(strings.TrimSpace(status))
	if status != "active" && s.ghApp != nil {
		s.ghApp.InvalidateInstallationToken(installationID)
	}
	if s.instRepo == nil {
		return nil, domain.ErrInstallationNotFound
	}
	inst, err := s.instRepo.GetGitHubInstallationByInstallationID(ctx, installationID)
	if err != nil {
		return nil, err
	}
	if err := s.instRepo.UpdateGitHubInstallationStatus(ctx, installationID, status); err != nil {
		return nil, err
	}
	inst.Status = status
	return inst, nil
}

// GetGitHubInstallationByInstallationID returns an installation by its GitHub installation ID.
func (s *Service) GetGitHubInstallationByInstallationID(ctx context.Context, installationID int64) (*domain.GitHubInstallation, error) {
	if s.instRepo == nil {
		return nil, domain.ErrInstallationNotFound
	}
	return s.instRepo.GetGitHubInstallationByInstallationID(ctx, installationID)
}

// InvalidateGitHubInstallationToken clears any cached token for installationID.
func (s *Service) InvalidateGitHubInstallationToken(installationID int64) {
	if s.ghApp != nil {
		s.ghApp.InvalidateInstallationToken(installationID)
	}
}

// ListRepositories retrieves all repositories accessible to the organization's GitHub installation.
func (s *Service) ListRepositories(ctx context.Context, caller *authv1.CallerPrincipal, orgID string, installationID int64) ([]client.Repository, error) {
	tok, _, _, err := s.GetInstallationToken(ctx, caller, orgID, installationID)
	if err != nil {
		return nil, err
	}
	if s.ghClient == nil {
		return nil, nil
	}
	return s.ghClient.ListRepositories(ctx, tok)
}

// ListBranches retrieves repository branches for owner/repo.
func (s *Service) ListBranches(ctx context.Context, caller *authv1.CallerPrincipal, orgID string, installationID int64, owner, repo string) ([]client.Branch, error) {
	if err := validateOwnerRepo(owner, repo); err != nil {
		return nil, err
	}
	tok, _, _, err := s.GetInstallationToken(ctx, caller, orgID, installationID)
	if err != nil {
		return nil, err
	}
	if s.ghClient == nil {
		return nil, nil
	}
	return s.ghClient.ListBranches(ctx, tok, owner, repo)
}

// ListDirectories retrieves canonical directory paths for owner/repo at ref along with detected presets.
func (s *Service) ListDirectories(ctx context.Context, caller *authv1.CallerPrincipal, orgID string, installationID int64, owner, repo, ref string, targetPath string) (*client.DirectoryDiscoveryResult, error) {
	if err := validateOwnerRepo(owner, repo); err != nil {
		return nil, err
	}
	if err := validateRef(ref); err != nil {
		return nil, err
	}
	if err := validatePath(targetPath); err != nil {
		return nil, err
	}
	tok, _, _, err := s.GetInstallationToken(ctx, caller, orgID, installationID)
	if err != nil {
		return nil, err
	}
	if s.ghClient == nil {
		return &client.DirectoryDiscoveryResult{}, nil
	}

	if explorer, ok := s.ghClient.(interface {
		ExploreDirectory(ctx context.Context, token string, owner, repo, ref, targetPath string) (*client.DirectoryDiscoveryResult, error)
	}); ok {
		return explorer.ExploreDirectory(ctx, tok, owner, repo, ref, targetPath)
	}

	if withPresets, ok := s.ghClient.(interface {
		ListDirectoriesWithPresets(ctx context.Context, token string, owner, repo, ref string) ([]string, map[string]string, error)
	}); ok {
		dirs, presets, err := withPresets.ListDirectoriesWithPresets(ctx, tok, owner, repo, ref)
		if err != nil {
			return nil, err
		}
		return &client.DirectoryDiscoveryResult{
			CurrentDirectory: client.DirectoryInfo{Path: "/", Name: "/", ParentPath: "/"},
			Directories:      dirs,
			Presets:          presets,
		}, nil
	}

	dirs, err := s.ghClient.ListDirectories(ctx, tok, owner, repo, ref)
	if err != nil {
		return nil, err
	}
	return &client.DirectoryDiscoveryResult{
		CurrentDirectory: client.DirectoryInfo{Path: "/", Name: "/", ParentPath: "/"},
		Directories:      dirs,
	}, nil
}

func validatePath(raw string) error {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" || trimmed == "." || trimmed == "/" || trimmed == "./" {
		return nil
	}
	if strings.Contains(trimmed, "\\") || strings.ContainsAny(trimmed, "\x00\r\n") {
		return fmt.Errorf("%w: invalid directory path %q", client.ErrInvalidInput, raw)
	}
	for _, seg := range strings.Split(trimmed, "/") {
		if seg == ".." {
			return fmt.Errorf("%w: path traversal in directory path %q", client.ErrInvalidInput, raw)
		}
	}
	return nil
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
		return nil
	}
	if strings.Contains(r, "..") || strings.ContainsAny(r, " \t\r\n~^:?*[\\]") {
		return fmt.Errorf("%w: invalid git ref %q", client.ErrInvalidInput, ref)
	}
	return nil
}
