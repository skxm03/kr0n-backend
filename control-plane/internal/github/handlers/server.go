package handlers

import (
	"context"
	"errors"

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

// ListDirectories returns canonical root directory paths for owner/repo at ref.
func (s *Server) ListDirectories(ctx context.Context, req *githubv1.ListDirectoriesRequest) (*githubv1.ListDirectoriesResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request cannot be nil")
	}

	dirs, err := s.svc.ListDirectories(ctx, req.GetCaller(), req.GetOrgId(), req.GetInstallationId(), req.GetOwner(), req.GetRepo(), req.GetRef())
	if err != nil {
		return nil, mapError(err)
	}

	return &githubv1.ListDirectoriesResponse{Directories: dirs}, nil
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
