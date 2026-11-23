package handlers

import (
	"context"
	"errors"
	"log"
	"strings"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	authv1 "github.com/skxm03/kr0n-backend/control-plane/gen/auth/v1"
	servicemanagerv1 "github.com/skxm03/kr0n-backend/control-plane/gen/servicemanager/v1"
	"github.com/skxm03/kr0n-backend/control-plane/internal/servicemanager/domain"
	"github.com/skxm03/kr0n-backend/control-plane/internal/servicemanager/service"
	pkgAudit "github.com/skxm03/kr0n-backend/control-plane/pkg/audit"
	"github.com/skxm03/kr0n-backend/control-plane/pkg/authz"
	"github.com/skxm03/kr0n-backend/control-plane/pkg/grpcauth"
)

// Option configures Server.
type Option func(*Server)

// WithAuditEmitter configures an asynchronous RabbitMQ audit emitter for the Service Manager gRPC server.
func WithAuditEmitter(emitter pkgAudit.Emitter) Option {
	return func(s *Server) {
		s.auditEmitter = emitter
	}
}

// WithServiceAuthConfig configures transport authentication policy for the Service Manager gRPC server.
func WithServiceAuthConfig(cfg grpcauth.ServiceAuthConfig) Option {
	return func(s *Server) {
		s.serviceAuth = cfg
	}
}

// Server implements servicemanagerv1.ServiceManagerServiceServer.
type Server struct {
	servicemanagerv1.UnimplementedServiceManagerServiceServer
	projectService *service.ProjectService
	auditEmitter   pkgAudit.Emitter
	serviceAuth    grpcauth.ServiceAuthConfig
}

// NewServer creates a new Service Manager gRPC server.
func NewServer(projectService *service.ProjectService, opts ...Option) *Server {
	s := &Server{projectService: projectService}
	for _, opt := range opts {
		if opt != nil {
			opt(s)
		}
	}
	return s
}

// ListApplicationPresets returns the catalog of Railpack-aligned application presets and their default build commands.
func (s *Server) ListApplicationPresets(_ context.Context, _ *servicemanagerv1.ListApplicationPresetsRequest) (*servicemanagerv1.ListApplicationPresetsResponse, error) {
	specs := domain.ListPresets()
	out := make([]*servicemanagerv1.ApplicationPresetInfo, 0, len(specs))
	for _, sp := range specs {
		out = append(out, &servicemanagerv1.ApplicationPresetInfo{
			Id:                     sp.ID,
			DisplayName:            sp.DisplayName,
			RailpackProvider:       sp.RailpackProvider,
			Category:               string(sp.Category),
			DefaultInstallCommand:  sp.DefaultInstallCommand,
			DefaultBuildCommand:    sp.DefaultBuildCommand,
			DefaultOutputDirectory: sp.DefaultOutputDirectory,
			DefaultRunCommand:      sp.DefaultRunCommand,
		})
	}
	return &servicemanagerv1.ListApplicationPresetsResponse{Presets: out}, nil
}

// CreateProject creates a new repository-linked project and its initial 1:1 build settings at revision 1.
func (s *Server) CreateProject(ctx context.Context, req *servicemanagerv1.CreateProjectRequest) (*servicemanagerv1.CreateProjectResponse, error) {
	p, orgID, err := s.parseOrgCall(ctx, req.GetCaller(), req.GetOrgId())
	if err != nil {
		return nil, err
	}

	var bs domain.BuildSettings
	if in := req.GetBuildSettings(); in != nil {
		bs = domain.BuildSettings{
			InstallCommand:          in.GetInstallCommand(),
			InstallCommandOverride:  in.GetInstallCommandOverride(),
			BuildCommand:            in.GetBuildCommand(),
			BuildCommandOverride:    in.GetBuildCommandOverride(),
			RunCommand:              in.GetRunCommand(),
			RunCommandOverride:      in.GetRunCommandOverride(),
			OutputDirectory:         in.GetOutputDirectory(),
			OutputDirectoryOverride: in.GetOutputDirectoryOverride(),
		}
	}

	proj, err := s.projectService.CreateProject(ctx, p, service.CreateProjectParams{
		OrganizationID:       orgID,
		Name:                 req.GetName(),
		Slug:                 req.GetSlug(),
		Description:          req.GetDescription(),
		GitHubInstallationID: req.GetGithubInstallationId(),
		RepoID:               req.GetRepoId(),
		RepoOwner:            req.GetRepoOwner(),
		RepoName:             req.GetRepoName(),
		ProductionBranch:     req.GetProductionBranch(),
		RootDirectory:        req.GetRootDirectory(),
		ApplicationPreset:    req.GetApplicationPreset(),
		BuildSettings:        bs,
	})
	if err != nil {
		return nil, mapDomainError(err)
	}

	s.emitAudit(ctx, p, orgID, pkgAudit.ActionProjectCreated, proj, map[string]any{
		"slug":               proj.Slug,
		"repo_full_name":     proj.RepoFullName(),
		"production_branch":  proj.ProductionBranch,
		"root_directory":     proj.RootDirectory,
		"application_preset": proj.ApplicationPreset,
		"revision":           proj.Revision,
	})

	return &servicemanagerv1.CreateProjectResponse{
		Project: toProjectProto(proj),
	}, nil
}

// ListProjects lists projects in an organization ordered newest-first.
func (s *Server) ListProjects(ctx context.Context, req *servicemanagerv1.ListProjectsRequest) (*servicemanagerv1.ListProjectsResponse, error) {
	p, orgID, err := s.parseOrgCall(ctx, req.GetCaller(), req.GetOrgId())
	if err != nil {
		return nil, err
	}
	projects, err := s.projectService.ListProjects(ctx, p, orgID, int(req.GetLimit()), int(req.GetOffset()))
	if err != nil {
		return nil, mapDomainError(err)
	}
	out := make([]*servicemanagerv1.ProjectInfo, 0, len(projects))
	for i := range projects {
		out = append(out, toProjectProto(&projects[i]))
	}
	return &servicemanagerv1.ListProjectsResponse{Projects: out}, nil
}

// GetProject retrieves a single project and its build settings by ID.
func (s *Server) GetProject(ctx context.Context, req *servicemanagerv1.GetProjectRequest) (*servicemanagerv1.GetProjectResponse, error) {
	p, orgID, err := s.parseOrgCall(ctx, req.GetCaller(), req.GetOrgId())
	if err != nil {
		return nil, err
	}
	projectID, err := uuid.Parse(strings.TrimSpace(req.GetProjectId()))
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid project_id")
	}
	proj, err := s.projectService.GetProject(ctx, p, orgID, projectID)
	if err != nil {
		return nil, mapDomainError(err)
	}
	return &servicemanagerv1.GetProjectResponse{
		Project: toProjectProto(proj),
	}, nil
}

// UpdateProject updates a project's metadata, root directory, branch, or preset, and increments revision.
func (s *Server) UpdateProject(ctx context.Context, req *servicemanagerv1.UpdateProjectRequest) (*servicemanagerv1.UpdateProjectResponse, error) {
	p, orgID, err := s.parseOrgCall(ctx, req.GetCaller(), req.GetOrgId())
	if err != nil {
		return nil, err
	}
	projectID, err := uuid.Parse(strings.TrimSpace(req.GetProjectId()))
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid project_id")
	}

	var descPtr *string
	if req.GetDescription() != "" {
		d := req.GetDescription()
		descPtr = &d
	}

	proj, err := s.projectService.UpdateProject(ctx, p, service.UpdateProjectParams{
		OrganizationID:    orgID,
		ProjectID:         projectID,
		Name:              req.GetName(),
		Description:       descPtr,
		ProductionBranch:  req.GetProductionBranch(),
		RootDirectory:     req.GetRootDirectory(),
		ApplicationPreset: req.GetApplicationPreset(),
		ExpectedRevision:  req.GetExpectedRevision(),
	})
	if err != nil {
		return nil, mapDomainError(err)
	}

	s.emitAudit(ctx, p, orgID, pkgAudit.ActionProjectUpdated, proj, map[string]any{
		"slug":               proj.Slug,
		"production_branch":  proj.ProductionBranch,
		"root_directory":     proj.RootDirectory,
		"application_preset": proj.ApplicationPreset,
		"revision":           proj.Revision,
	})

	return &servicemanagerv1.UpdateProjectResponse{
		Project: toProjectProto(proj),
	}, nil
}

// UpdateProjectBuildSettings updates a project's toggleable build settings and increments revision.
func (s *Server) UpdateProjectBuildSettings(ctx context.Context, req *servicemanagerv1.UpdateProjectBuildSettingsRequest) (*servicemanagerv1.UpdateProjectBuildSettingsResponse, error) {
	p, orgID, err := s.parseOrgCall(ctx, req.GetCaller(), req.GetOrgId())
	if err != nil {
		return nil, err
	}
	projectID, err := uuid.Parse(strings.TrimSpace(req.GetProjectId()))
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid project_id")
	}

	var bs domain.BuildSettings
	if in := req.GetBuildSettings(); in != nil {
		bs = domain.BuildSettings{
			InstallCommand:          in.GetInstallCommand(),
			InstallCommandOverride:  in.GetInstallCommandOverride(),
			BuildCommand:            in.GetBuildCommand(),
			BuildCommandOverride:    in.GetBuildCommandOverride(),
			RunCommand:              in.GetRunCommand(),
			RunCommandOverride:      in.GetRunCommandOverride(),
			OutputDirectory:         in.GetOutputDirectory(),
			OutputDirectoryOverride: in.GetOutputDirectoryOverride(),
		}
	}

	proj, err := s.projectService.UpdateProjectBuildSettings(ctx, p, orgID, projectID, req.GetExpectedRevision(), bs)
	if err != nil {
		return nil, mapDomainError(err)
	}

	s.emitAudit(ctx, p, orgID, pkgAudit.ActionProjectBuildSettingsUpdated, proj, map[string]any{
		"slug":                      proj.Slug,
		"install_command_override":  proj.BuildSettings.InstallCommandOverride,
		"build_command_override":    proj.BuildSettings.BuildCommandOverride,
		"output_directory_override": proj.BuildSettings.OutputDirectoryOverride,
		"revision":                  proj.Revision,
	})

	return &servicemanagerv1.UpdateProjectBuildSettingsResponse{
		Project: toProjectProto(proj),
	}, nil
}

// DeleteProject deletes a project and its build settings.
func (s *Server) DeleteProject(ctx context.Context, req *servicemanagerv1.DeleteProjectRequest) (*servicemanagerv1.DeleteProjectResponse, error) {
	p, orgID, err := s.parseOrgCall(ctx, req.GetCaller(), req.GetOrgId())
	if err != nil {
		return nil, err
	}
	projectID, err := uuid.Parse(strings.TrimSpace(req.GetProjectId()))
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid project_id")
	}

	if err := s.projectService.DeleteProject(ctx, p, orgID, projectID); err != nil {
		return nil, mapDomainError(err)
	}

	s.emitAudit(ctx, p, orgID, pkgAudit.ActionProjectDeleted, &domain.Project{
		ID:             projectID,
		OrganizationID: orgID,
	}, map[string]any{
		"project_id": projectID.String(),
	})

	return &servicemanagerv1.DeleteProjectResponse{
		Message: "project deleted successfully",
	}, nil
}

func (s *Server) parseOrgCall(ctx context.Context, c *authv1.CallerPrincipal, rawOrgID string) (domain.Principal, uuid.UUID, error) {
	if s.projectService == nil {
		return domain.Principal{}, uuid.Nil, status.Error(codes.Unimplemented, "project service not configured")
	}
	return authz.ParseOrgCall(ctx, s.serviceAuth, c, rawOrgID)
}

func (s *Server) emitAudit(ctx context.Context, p domain.Principal, orgID uuid.UUID, action pkgAudit.Action, proj *domain.Project, meta map[string]any) {
	if s.auditEmitter == nil || proj == nil {
		return
	}

	actorType := pkgAudit.ActorTypeUser
	if p.Kind == pkgAudit.ActorTypeAPIToken {
		actorType = pkgAudit.ActorTypeAPIToken
	}

	clientCtx := pkgAudit.ExtractClientContext(ctx)
	actorID := p.UserID

	if err := s.auditEmitter.Emit(ctx, pkgAudit.Event{
		Service:        pkgAudit.ServiceServiceManager,
		Action:         action.String(),
		Status:         pkgAudit.StatusSuccess,
		OrganizationID: &orgID,
		Actor: pkgAudit.Actor{
			UserID: &actorID,
			Type:   actorType,
		},
		Target: pkgAudit.Target{
			Type: pkgAudit.TargetTypeProject,
			ID:   proj.ID.String(),
			Name: proj.Slug,
		},
		ClientContext: clientCtx,
		Metadata:      meta,
	}); err != nil {
		log.Printf("servicemanager audit emit error (%s): %v", action, err)
	}
}

func toProjectProto(p *domain.Project) *servicemanagerv1.ProjectInfo {
	if p == nil {
		return nil
	}
	var repoID int64
	if p.RepoID != nil {
		repoID = *p.RepoID
	}
	var createdBy string
	if p.CreatedByUserID != nil {
		createdBy = p.CreatedByUserID.String()
	}

	eff := domain.ResolveEffectiveBuildSettings(p.ApplicationPreset, p.BuildSettings)

	return &servicemanagerv1.ProjectInfo{
		Id:                   p.ID.String(),
		OrgId:                p.OrganizationID.String(),
		Name:                 p.Name,
		Slug:                 p.Slug,
		Description:          p.Description,
		GithubInstallationId: p.GitHubInstallationID,
		RepoId:               repoID,
		RepoOwner:            p.RepoOwner,
		RepoName:             p.RepoName,
		RepoFullName:         p.RepoFullName(),
		ProductionBranch:     p.ProductionBranch,
		RootDirectory:        p.RootDirectory,
		ApplicationPreset:    p.ApplicationPreset,
		Revision:             p.Revision,
		CreatedByUserId:      createdBy,
		CreatedAt:            timestamppb.New(p.CreatedAt),
		UpdatedAt:            timestamppb.New(p.UpdatedAt),
		BuildSettings: &servicemanagerv1.BuildSettingsInfo{
			InstallCommand:           p.BuildSettings.InstallCommand,
			InstallCommandOverride:   p.BuildSettings.InstallCommandOverride,
			BuildCommand:             p.BuildSettings.BuildCommand,
			BuildCommandOverride:     p.BuildSettings.BuildCommandOverride,
			RunCommand:               p.BuildSettings.RunCommand,
			RunCommandOverride:       p.BuildSettings.RunCommandOverride,
			OutputDirectory:          p.BuildSettings.OutputDirectory,
			OutputDirectoryOverride:  p.BuildSettings.OutputDirectoryOverride,
			EffectiveInstallCommand:  eff.InstallCommand,
			EffectiveBuildCommand:    eff.BuildCommand,
			EffectiveRunCommand:      eff.RunCommand,
			EffectiveOutputDirectory: eff.OutputDirectory,
			UpdatedAt:                timestamppb.New(p.BuildSettings.UpdatedAt),
		},
	}
}

func mapDomainError(err error) error {
	switch {
	case errors.Is(err, domain.ErrForbidden):
		return status.Error(codes.PermissionDenied, "permission denied")
	case errors.Is(err, domain.ErrProjectNotFound):
		return status.Error(codes.NotFound, "project not found")
	case errors.Is(err, domain.ErrProjectSlugConflict):
		return status.Error(codes.AlreadyExists, "project slug already exists in this organization")
	case errors.Is(err, domain.ErrRevisionConflict):
		return status.Error(codes.Aborted, "project revision conflict: project was modified by another request")
	case errors.Is(err, domain.ErrInvalidProject),
		errors.Is(err, domain.ErrInvalidPreset),
		errors.Is(err, domain.ErrInvalidRootDirectory),
		errors.Is(err, domain.ErrInstallationNotLinked):
		return status.Error(codes.InvalidArgument, err.Error())
	default:
		log.Printf("servicemanager internal error: %v", err)
		return status.Error(codes.Internal, "internal server error")
	}
}
