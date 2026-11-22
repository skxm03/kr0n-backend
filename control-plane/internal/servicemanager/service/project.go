package service

import (
	"context"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/skxm03/kr0n-backend/control-plane/internal/servicemanager/domain"
	"github.com/skxm03/kr0n-backend/control-plane/internal/servicemanager/repository"
)

// CreateProjectParams holds input fields for creating a new project and its build settings.
type CreateProjectParams struct {
	OrganizationID       uuid.UUID
	Name                 string
	Slug                 string
	Description          string
	GitHubInstallationID int64
	RepoID               int64
	RepoOwner            string
	RepoName             string
	ProductionBranch     string
	RootDirectory        string
	ApplicationPreset    string
	BuildSettings        domain.BuildSettings
}

// UpdateProjectParams holds input fields for updating a project's metadata and preset.
type UpdateProjectParams struct {
	OrganizationID    uuid.UUID
	ProjectID         uuid.UUID
	Name              string
	Description       *string
	ProductionBranch  string
	RootDirectory     string
	ApplicationPreset string
	ExpectedRevision  int64
}

// Option configures a ProjectService instance.
type Option func(*ProjectService)

// WithAuthorizer configures an external Authorizer for RBAC evaluations.
func WithAuthorizer(a Authorizer) Option {
	return func(s *ProjectService) {
		s.authorizer = a
	}
}

// WithInstallationVerifier configures an external InstallationVerifier for GitHub installations.
func WithInstallationVerifier(v InstallationVerifier) Option {
	return func(s *ProjectService) {
		s.installationVerifier = v
	}
}

// ProjectService orchestrates RBAC authorization, validation, and persistence for Projects & BuildSettings.
type ProjectService struct {
	repo                 repository.ProjectRepository
	authorizer           Authorizer
	installationVerifier InstallationVerifier
}

// NewProjectService creates a new ProjectService.
func NewProjectService(repo repository.ProjectRepository, opts ...Option) *ProjectService {
	s := &ProjectService{repo: repo}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// Can checks whether caller principal p holds permission in orgID.
func (s *ProjectService) Can(ctx context.Context, p domain.Principal, orgID uuid.UUID, permission string) (bool, error) {
	if p.UserID == uuid.Nil || orgID == uuid.Nil || permission == "" {
		return false, nil
	}
	if p.Kind == "api_token" {
		if p.TokenOrgID == nil || *p.TokenOrgID != orgID || !hasPermission(p.TokenPermissions, permission) {
			return false, nil
		}
	}

	if s.authorizer != nil {
		return s.authorizer.CheckPermission(ctx, p, orgID, permission)
	}
	return false, nil
}

func (s *ProjectService) require(ctx context.Context, p domain.Principal, orgID uuid.UUID, permission string) error {
	allowed, err := s.Can(ctx, p, orgID, permission)
	if err != nil {
		return err
	}
	if !allowed {
		return domain.ErrForbidden
	}
	return nil
}

func hasPermission(perms []string, permission string) bool {
	for _, perm := range perms {
		if perm == permission {
			return true
		}
	}
	return false
}

// ListPresets returns the supported Railpack application preset catalog.
func (s *ProjectService) ListPresets() []domain.PresetSpec {
	return domain.ListPresets()
}

// CreateProject authorizes caller with `project:create`, validates installation ownership, repository fields,
// root directory, and application preset, and creates the project + build settings at revision 1.
func (s *ProjectService) CreateProject(ctx context.Context, p domain.Principal, params CreateProjectParams) (*domain.Project, error) {
	if err := s.require(ctx, p, params.OrganizationID, "project:create"); err != nil {
		return nil, err
	}

	name := strings.TrimSpace(params.Name)
	if len(name) < 1 || len(name) > 100 {
		return nil, domain.ErrInvalidProject
	}

	slug := strings.ToLower(strings.TrimSpace(params.Slug))
	if slug == "" {
		slug = domain.DeriveProjectSlug(name)
	}
	if !domain.ValidateProjectSlug(slug) {
		return nil, domain.ErrInvalidProject
	}

	description := strings.TrimSpace(params.Description)
	if len(description) > 500 {
		return nil, domain.ErrInvalidProject
	}

	repoOwner := strings.TrimSpace(params.RepoOwner)
	repoName := strings.TrimSpace(params.RepoName)
	if repoOwner == "" || repoName == "" || strings.Contains(repoOwner, "/") || strings.Contains(repoName, "/") {
		return nil, domain.ErrInvalidProject
	}

	if params.GitHubInstallationID <= 0 {
		return nil, domain.ErrInstallationNotLinked
	}
	if s.installationVerifier != nil {
		active, err := s.installationVerifier.VerifyActiveOrgInstallation(ctx, params.OrganizationID, params.GitHubInstallationID)
		if err != nil {
			return nil, err
		}
		if !active {
			return nil, domain.ErrInstallationNotLinked
		}
	}

	branch := strings.TrimSpace(params.ProductionBranch)
	if branch == "" {
		branch = "main"
	}

	rootDir, err := domain.NormalizeRootDirectory(params.RootDirectory)
	if err != nil {
		return nil, err
	}

	presetID := strings.ToLower(strings.TrimSpace(params.ApplicationPreset))
	if presetID == "" {
		presetID = "auto"
	}
	if _, ok := domain.LookupPreset(presetID); !ok {
		return nil, domain.ErrInvalidPreset
	}

	var repoIDPtr *int64
	if params.RepoID > 0 {
		rid := params.RepoID
		repoIDPtr = &rid
	}

	now := time.Now().UTC()
	creatorID := p.UserID
	projID := uuid.New()

	bs := params.BuildSettings
	bs.ProjectID = projID
	bs.UpdatedAt = now
	// When an override toggle is OFF (false), clear stored override text so preset/Railpack defaults apply cleanly.
	if !bs.InstallCommandOverride {
		bs.InstallCommand = ""
	}
	if !bs.BuildCommandOverride {
		bs.BuildCommand = ""
	}
	if !bs.OutputDirectoryOverride {
		bs.OutputDirectory = ""
	}

	proj := &domain.Project{
		ID:                   projID,
		OrganizationID:       params.OrganizationID,
		Name:                 name,
		Slug:                 slug,
		Description:          description,
		GitHubInstallationID: params.GitHubInstallationID,
		RepoID:               repoIDPtr,
		RepoOwner:            repoOwner,
		RepoName:             repoName,
		ProductionBranch:     branch,
		RootDirectory:        rootDir,
		ApplicationPreset:    presetID,
		Revision:             1,
		CreatedByUserID:      &creatorID,
		CreatedAt:            now,
		UpdatedAt:            now,
		BuildSettings:        bs,
	}

	return s.repo.CreateProject(ctx, proj)
}

// GetProject retrieves a project if the caller holds `project:read`.
func (s *ProjectService) GetProject(ctx context.Context, p domain.Principal, orgID, projectID uuid.UUID) (*domain.Project, error) {
	if err := s.require(ctx, p, orgID, "project:read"); err != nil {
		return nil, err
	}
	return s.repo.GetProject(ctx, orgID, projectID)
}

// ListProjects lists projects in orgID if the caller holds `project:read`.
func (s *ProjectService) ListProjects(ctx context.Context, p domain.Principal, orgID uuid.UUID, limit, offset int) ([]domain.Project, error) {
	if err := s.require(ctx, p, orgID, "project:read"); err != nil {
		return nil, err
	}
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}
	return s.repo.ListProjects(ctx, orgID, limit, offset)
}

// UpdateProject updates a project's metadata, branch, root directory, or preset if the caller holds `project:update`,
// enforcing optional optimistic concurrency (`expected_revision`) and incrementing `revision`.
func (s *ProjectService) UpdateProject(ctx context.Context, p domain.Principal, params UpdateProjectParams) (*domain.Project, error) {
	if err := s.require(ctx, p, params.OrganizationID, "project:update"); err != nil {
		return nil, err
	}

	existing, err := s.repo.GetProject(ctx, params.OrganizationID, params.ProjectID)
	if err != nil {
		return nil, err
	}
	if params.ExpectedRevision > 0 && existing.Revision != params.ExpectedRevision {
		return nil, domain.ErrRevisionConflict
	}

	name := strings.TrimSpace(params.Name)
	if name == "" {
		name = existing.Name
	}
	if len(name) < 1 || len(name) > 100 {
		return nil, domain.ErrInvalidProject
	}

	desc := existing.Description
	if params.Description != nil {
		desc = strings.TrimSpace(*params.Description)
		if len(desc) > 500 {
			return nil, domain.ErrInvalidProject
		}
	}

	branch := strings.TrimSpace(params.ProductionBranch)
	if branch == "" {
		branch = existing.ProductionBranch
	}

	rootDir := existing.RootDirectory
	if strings.TrimSpace(params.RootDirectory) != "" {
		normalized, err := domain.NormalizeRootDirectory(params.RootDirectory)
		if err != nil {
			return nil, err
		}
		rootDir = normalized
	}

	presetID := existing.ApplicationPreset
	if strings.TrimSpace(params.ApplicationPreset) != "" {
		candidate := strings.ToLower(strings.TrimSpace(params.ApplicationPreset))
		if _, ok := domain.LookupPreset(candidate); !ok {
			return nil, domain.ErrInvalidPreset
		}
		presetID = candidate
	}

	return s.repo.UpdateProject(ctx, repository.UpdateProjectMutation{
		OrganizationID:    params.OrganizationID,
		ProjectID:         params.ProjectID,
		Name:              name,
		Description:       desc,
		ProductionBranch:  branch,
		RootDirectory:     rootDir,
		ApplicationPreset: presetID,
		ExpectedRevision:  params.ExpectedRevision,
		UpdatedAt:         time.Now().UTC(),
	})
}

// UpdateProjectBuildSettings updates a project's toggleable build settings and increments `revision` if caller holds `project:update`.
func (s *ProjectService) UpdateProjectBuildSettings(
	ctx context.Context,
	p domain.Principal,
	orgID, projectID uuid.UUID,
	expectedRevision int64,
	bs domain.BuildSettings,
) (*domain.Project, error) {
	if err := s.require(ctx, p, orgID, "project:update"); err != nil {
		return nil, err
	}
	bs.ProjectID = projectID
	bs.UpdatedAt = time.Now().UTC()
	if !bs.InstallCommandOverride {
		bs.InstallCommand = ""
	}
	if !bs.BuildCommandOverride {
		bs.BuildCommand = ""
	}
	if !bs.OutputDirectoryOverride {
		bs.OutputDirectory = ""
	}
	return s.repo.UpdateBuildSettings(ctx, orgID, projectID, expectedRevision, bs)
}

// DeleteProject deletes a project if the caller holds `project:delete`.
func (s *ProjectService) DeleteProject(ctx context.Context, p domain.Principal, orgID, projectID uuid.UUID) error {
	if err := s.require(ctx, p, orgID, "project:delete"); err != nil {
		return err
	}
	return s.repo.DeleteProject(ctx, orgID, projectID)
}
