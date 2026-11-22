package handlers

import (
	"context"
	"errors"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	authv1 "github.com/skxm03/kr0n-backend/control-plane/gen/auth/v1"
	githubv1 "github.com/skxm03/kr0n-backend/control-plane/gen/github/v1"
	"github.com/skxm03/kr0n-backend/control-plane/internal/github/client"
	"github.com/skxm03/kr0n-backend/control-plane/internal/github/domain"
	"github.com/skxm03/kr0n-backend/control-plane/internal/github/provider"
	"github.com/skxm03/kr0n-backend/control-plane/internal/github/service"
	"github.com/skxm03/kr0n-backend/control-plane/internal/github/webhook"
	pkgAudit "github.com/skxm03/kr0n-backend/control-plane/pkg/audit"
)

// Option configures Server.
type Option func(*Server)

// WithAuditEmitter configures an asynchronous RabbitMQ audit emitter for the GitHub gRPC server.
func WithAuditEmitter(emitter pkgAudit.Emitter) Option {
	return func(s *Server) {
		s.auditEmitter = emitter
	}
}

// Server implements githubv1.GitHubServiceServer.
type Server struct {
	githubv1.UnimplementedGitHubServiceServer
	svc          *service.Service
	auditEmitter pkgAudit.Emitter
}

// NewServer constructs a new GitHubServiceServer handler instance.
func NewServer(svc *service.Service, opts ...Option) *Server {
	s := &Server{svc: svc}
	for _, opt := range opts {
		if opt != nil {
			opt(s)
		}
	}
	return s
}

// StartGitHubInstallation generates a signed installation state token and GitHub App installation URL.
func (s *Server) StartGitHubInstallation(ctx context.Context, req *githubv1.StartGitHubInstallationRequest) (*githubv1.StartGitHubInstallationResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request cannot be nil")
	}
	url, state, err := s.svc.StartGitHubInstallation(ctx, req.GetCaller(), req.GetOrgId())
	if err != nil {
		return nil, mapError(err)
	}
	return &githubv1.StartGitHubInstallationResponse{
		InstallUrl: url,
		State:      state,
	}, nil
}

// CompleteGitHubInstallation verifies installation state and links the GitHub App installation.
func (s *Server) CompleteGitHubInstallation(ctx context.Context, req *githubv1.CompleteGitHubInstallationRequest) (*githubv1.CompleteGitHubInstallationResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request cannot be nil")
	}
	inst, err := s.svc.CompleteGitHubInstallation(ctx, req.GetCaller(), req.GetOrgId(), req.GetInstallationId(), req.GetState())
	if err != nil {
		return nil, mapError(err)
	}

	if orgID, parseErr := uuid.Parse(strings.TrimSpace(req.GetOrgId())); parseErr == nil {
		s.emitAudit(ctx, req.GetCaller(), orgID, pkgAudit.ActionGitHubInstallationConnected, strconv.FormatInt(inst.InstallationID, 10), map[string]any{
			"installation_id": inst.InstallationID,
			"account_login":   inst.AccountLogin,
			"account_type":    inst.AccountType,
		})
	}

	return &githubv1.CompleteGitHubInstallationResponse{
		Installation: toProtoInstallation(inst),
	}, nil
}

// ListGitHubInstallations lists GitHub installations linked to an organization.
func (s *Server) ListGitHubInstallations(ctx context.Context, req *githubv1.ListGitHubInstallationsRequest) (*githubv1.ListGitHubInstallationsResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request cannot be nil")
	}
	list, err := s.svc.ListGitHubInstallations(ctx, req.GetCaller(), req.GetOrgId())
	if err != nil {
		return nil, mapError(err)
	}
	out := make([]*githubv1.GitHubInstallationInfo, 0, len(list))
	for i := range list {
		out = append(out, toProtoInstallation(&list[i]))
	}
	return &githubv1.ListGitHubInstallationsResponse{Installations: out}, nil
}

// DisconnectGitHubInstallation unlinks a GitHub installation from an organization.
func (s *Server) DisconnectGitHubInstallation(ctx context.Context, req *githubv1.DisconnectGitHubInstallationRequest) (*githubv1.DisconnectGitHubInstallationResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request cannot be nil")
	}
	if err := s.svc.DisconnectGitHubInstallation(ctx, req.GetCaller(), req.GetOrgId(), req.GetInstallationId()); err != nil {
		return nil, mapError(err)
	}

	if orgID, parseErr := uuid.Parse(strings.TrimSpace(req.GetOrgId())); parseErr == nil {
		s.emitAudit(ctx, req.GetCaller(), orgID, pkgAudit.ActionGitHubInstallationDisconnected, strconv.FormatInt(req.GetInstallationId(), 10), map[string]any{
			"installation_id": req.GetInstallationId(),
		})
	}

	return &githubv1.DisconnectGitHubInstallationResponse{Message: "disconnected successfully"}, nil
}

// GetGitHubInstallationToken exchanges organization permissions and caller principal for a scoped token.
func (s *Server) GetGitHubInstallationToken(ctx context.Context, req *githubv1.GetGitHubInstallationTokenRequest) (*githubv1.GetGitHubInstallationTokenResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request cannot be nil")
	}
	tok, instID, exp, err := s.svc.GetInstallationToken(ctx, req.GetCaller(), req.GetOrgId(), req.GetInstallationId())
	if err != nil {
		return nil, mapError(err)
	}
	return &githubv1.GetGitHubInstallationTokenResponse{
		Token:          tok,
		InstallationId: instID,
		ExpiresAtUnix:  exp.Unix(),
	}, nil
}

// HandleGitHubWebhook processes raw GitHub App webhook deliveries over gRPC.
func (s *Server) HandleGitHubWebhook(ctx context.Context, req *githubv1.HandleGitHubWebhookRequest) (*githubv1.HandleGitHubWebhookResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request cannot be nil")
	}
	st, err := s.svc.HandleGitHubWebhook(ctx, req.GetPayload(), req.GetSignatureHeader(), req.GetEventType(), req.GetDeliveryId())
	if err != nil {
		return nil, mapError(err)
	}
	return &githubv1.HandleGitHubWebhookResponse{Status: st}, nil
}

// ListRepositories returns repositories accessible to the installation.
func (s *Server) ListRepositories(ctx context.Context, req *githubv1.ListRepositoriesRequest) (*githubv1.ListRepositoriesResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request cannot be nil")
	}

	repos, err := s.svc.ListRepositories(ctx, req.GetCaller(), req.GetOrgId(), req.GetInstallationId())
	if err != nil {
		return nil, mapError(err)
	}

	out := make([]*githubv1.GitHubRepositoryInfo, 0, len(repos))
	for _, r := range repos {
		out = append(out, &githubv1.GitHubRepositoryInfo{
			Id:            r.ID,
			Owner:         r.Owner,
			Name:          r.Name,
			FullName:      r.FullName,
			Private:       r.Private,
			DefaultBranch: r.DefaultBranch,
			HtmlUrl:       r.HTMLURL,
			UpdatedAt:     r.UpdatedAt,
			PushedAt:      r.PushedAt,
			Description:   r.Description,
			Language:      r.Language,
		})
	}
	return &githubv1.ListRepositoriesResponse{Repositories: out}, nil
}

// ListBranches returns branches for owner/repo.
func (s *Server) ListBranches(ctx context.Context, req *githubv1.ListBranchesRequest) (*githubv1.ListBranchesResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request cannot be nil")
	}

	branches, err := s.svc.ListBranches(ctx, req.GetCaller(), req.GetOrgId(), req.GetInstallationId(), req.GetOwner(), req.GetRepo())
	if err != nil {
		return nil, mapError(err)
	}

	out := make([]*githubv1.GitHubBranchInfo, 0, len(branches))
	for _, b := range branches {
		out = append(out, &githubv1.GitHubBranchInfo{
			Name:      b.Name,
			CommitSha: b.CommitSHA,
			Protected: b.Protected,
		})
	}
	return &githubv1.ListBranchesResponse{Branches: out}, nil
}

// ListDirectories returns canonical root directory paths for owner/repo at ref along with structured entries and tree.
func (s *Server) ListDirectories(ctx context.Context, req *githubv1.ListDirectoriesRequest) (*githubv1.ListDirectoriesResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request cannot be nil")
	}

	dirs, presets, err := s.svc.ListDirectories(ctx, req.GetCaller(), req.GetOrgId(), req.GetInstallationId(), req.GetOwner(), req.GetRepo(), req.GetRef())
	if err != nil {
		return nil, mapError(err)
	}

	entries := make([]*githubv1.DirectoryEntry, 0, len(dirs))
	nodeMap := make(map[string]*githubv1.DirectoryNode, len(dirs))

	rootPreset := ""
	if presets != nil {
		rootPreset = presets["/"]
	}

	rootNode := &githubv1.DirectoryNode{
		Path:           "/",
		Name:           "/",
		DetectedPreset: rootPreset,
	}
	nodeMap["/"] = rootNode

	for _, d := range dirs {
		if d == "/" {
			continue
		}
		var preset string
		if presets != nil {
			preset = presets[d]
		}

		lastSlash := strings.LastIndex(d, "/")
		var parentPath string
		var name string
		if lastSlash <= 0 {
			parentPath = "/"
			name = d[1:]
		} else {
			parentPath = d[:lastSlash]
			name = d[lastSlash+1:]
		}

		entries = append(entries, &githubv1.DirectoryEntry{
			Path:           d,
			Name:           name,
			ParentPath:     parentPath,
			DetectedPreset: preset,
		})

		node := &githubv1.DirectoryNode{
			Path:           d,
			Name:           name,
			DetectedPreset: preset,
		}
		nodeMap[d] = node

		if parent, exists := nodeMap[parentPath]; exists {
			parent.Children = append(parent.Children, node)
		} else {
			rootNode.Children = append(rootNode.Children, node)
		}
	}

	return &githubv1.ListDirectoriesResponse{
		Directories: dirs,
		Entries:     entries,
		Root:        rootNode,
	}, nil
}

func toProtoInstallation(inst *domain.GitHubInstallation) *githubv1.GitHubInstallationInfo {
	if inst == nil {
		return nil
	}
	return &githubv1.GitHubInstallationInfo{
		Id:                  inst.ID.String(),
		OrgId:               inst.OrganizationID.String(),
		InstallationId:      inst.InstallationID,
		AccountLogin:        inst.AccountLogin,
		AccountType:         inst.AccountType,
		RepositorySelection: inst.RepositorySelection,
		Status:              inst.Status,
		CreatedByUserId:     inst.CreatedByUserID.String(),
		CreatedAt:           timestamppb.New(inst.CreatedAt),
		UpdatedAt:           timestamppb.New(inst.UpdatedAt),
	}
}

func mapError(err error) error {
	if err == nil {
		return nil
	}
	if _, ok := status.FromError(err); ok {
		return err
	}

	switch {
	case errors.Is(err, client.ErrInvalidInput),
		errors.Is(err, domain.ErrInvalidInstallation),
		errors.Is(err, provider.ErrInvalidInstallationState),
		errors.Is(err, webhook.ErrInvalidPayload):
		return status.Error(codes.InvalidArgument, err.Error())

	case errors.Is(err, domain.ErrInstallationAlreadyLinked):
		return status.Error(codes.AlreadyExists, err.Error())

	case errors.Is(err, domain.ErrInstallationNotFound),
		errors.Is(err, provider.ErrInstallationNotFound),
		errors.Is(err, client.ErrNotFound):
		return status.Error(codes.NotFound, err.Error())

	case errors.Is(err, service.ErrPermissionDenied):
		return status.Error(codes.PermissionDenied, err.Error())

	case errors.Is(err, provider.ErrGitHubAppNotConfigured):
		return status.Error(codes.FailedPrecondition, err.Error())

	case errors.Is(err, webhook.ErrMissingSignature),
		errors.Is(err, webhook.ErrInvalidSignature),
		errors.Is(err, client.ErrUnauthorized):
		return status.Error(codes.Unauthenticated, err.Error())

	case errors.Is(err, webhook.ErrPayloadTooLarge),
		errors.Is(err, client.ErrRateLimited):
		return status.Error(codes.ResourceExhausted, err.Error())

	case errors.Is(err, provider.ErrGitHubAppAPI):
		return status.Error(codes.Unavailable, err.Error())

	case errors.Is(err, client.ErrUpstream):
		return status.Error(codes.Unavailable, "github upstream service unavailable")

	default:
		return status.Error(codes.Internal, "internal github service error")
	}
}

func (s *Server) emitAudit(ctx context.Context, caller *authv1.CallerPrincipal, orgID uuid.UUID, action pkgAudit.Action, resourceID string, meta map[string]any) {
	if s.auditEmitter == nil {
		return
	}
	actorType := pkgAudit.ActorTypeUser
	var actorUserID *uuid.UUID
	if caller != nil {
		if uid, err := uuid.Parse(strings.TrimSpace(caller.GetUserId())); err == nil {
			actorUserID = &uid
		}
		if caller.GetKind() == pkgAudit.ActorTypeAPIToken {
			actorType = pkgAudit.ActorTypeAPIToken
		}
	}
	clientCtx := pkgAudit.ExtractClientContext(ctx)
	_ = s.auditEmitter.Emit(ctx, pkgAudit.Event{
		Service:        pkgAudit.ServiceGitHub,
		Action:         action.String(),
		Status:         pkgAudit.StatusSuccess,
		OrganizationID: &orgID,
		Actor: pkgAudit.Actor{
			UserID: actorUserID,
			Type:   actorType,
		},
		Target: pkgAudit.Target{
			Type: pkgAudit.TargetTypeGitHubInstallation,
			ID:   resourceID,
		},
		ClientContext: clientCtx,
		Metadata:      meta,
	})
}
