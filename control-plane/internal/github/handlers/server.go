package handlers

import (
	"context"
	"errors"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	githubv1 "github.com/skxm03/kr0n-backend/control-plane/gen/github/v1"
	"github.com/skxm03/kr0n-backend/control-plane/internal/github/client"
	"github.com/skxm03/kr0n-backend/control-plane/internal/github/service"
)

// Server implements githubv1.GitHubServiceServer.
type Server struct {
	githubv1.UnimplementedGitHubServiceServer
	svc *service.Service
}

// NewServer constructs a new GitHubServiceServer handler instance.
func NewServer(svc *service.Service) *Server {
	return &Server{svc: svc}
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
		preset := ""
		if presets != nil {
			preset = presets[d]
		}

		if d == "/" {
			entries = append(entries, &githubv1.DirectoryEntry{
				Path:           "/",
				Name:           "/",
				ParentPath:     "",
				DetectedPreset: preset,
			})
			continue
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

func mapError(err error) error {
	if err == nil {
		return nil
	}
	// If the error is already a gRPC status error (e.g. forwarded from Auth Service), propagate it
	if _, ok := status.FromError(err); ok {
		return err
	}

	switch {
	case errors.Is(err, client.ErrInvalidInput):
		return status.Error(codes.InvalidArgument, err.Error())
	case errors.Is(err, client.ErrNotFound):
		return status.Error(codes.NotFound, err.Error())
	case errors.Is(err, client.ErrUnauthorized):
		return status.Error(codes.Unauthenticated, err.Error())
	case errors.Is(err, client.ErrRateLimited):
		return status.Error(codes.ResourceExhausted, "github api rate limit exceeded")
	case errors.Is(err, client.ErrUpstream):
		return status.Error(codes.Unavailable, "github upstream service unavailable")
	default:
		return status.Error(codes.Internal, "internal github service error")
	}
}
