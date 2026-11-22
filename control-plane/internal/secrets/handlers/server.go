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
	secretsv1 "github.com/skxm03/kr0n-backend/control-plane/gen/secrets/v1"
	"github.com/skxm03/kr0n-backend/control-plane/internal/secrets/domain"
	"github.com/skxm03/kr0n-backend/control-plane/internal/secrets/service"
	pkgAudit "github.com/skxm03/kr0n-backend/control-plane/pkg/audit"
	"github.com/skxm03/kr0n-backend/control-plane/pkg/grpcauth"
)

// Option configures Server.
type Option func(*Server)

// WithAuditEmitter configures an asynchronous RabbitMQ audit emitter for the Secrets gRPC server.
func WithAuditEmitter(emitter pkgAudit.Emitter) Option {
	return func(s *Server) {
		s.auditEmitter = emitter
	}
}

// WithServiceAuthConfig configures transport authentication policy for the Secrets gRPC server.
func WithServiceAuthConfig(cfg grpcauth.ServiceAuthConfig) Option {
	return func(s *Server) {
		s.serviceAuth = cfg
	}
}

// Server implements both secretsv1.SecretsServiceServer (public write-only API)
// and secretsv1.SecretsInternalServiceServer (restricted internal decryption for build/deploy runners).
type Server struct {
	secretsv1.UnimplementedSecretsServiceServer
	secretsv1.UnimplementedSecretsInternalServiceServer
	secretsService *service.SecretsService
	auditEmitter   pkgAudit.Emitter
	serviceAuth    grpcauth.ServiceAuthConfig
}

// NewServer creates a new Secrets gRPC server.
func NewServer(secretsService *service.SecretsService, opts ...Option) *Server {
	s := &Server{secretsService: secretsService}
	for _, opt := range opts {
		if opt != nil {
			opt(s)
		}
	}
	return s
}

// UpsertProjectEnvVars encrypts and upserts write-only project environment variables and returns masked metadata.
func (s *Server) UpsertProjectEnvVars(
	ctx context.Context,
	req *secretsv1.UpsertProjectEnvVarsRequest,
) (*secretsv1.UpsertProjectEnvVarsResponse, error) {
	p, orgID, err := s.parseOrgCall(ctx, req.GetCaller(), req.GetOrgId())
	if err != nil {
		return nil, err
	}
	projectID, err := uuid.Parse(strings.TrimSpace(req.GetProjectId()))
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid project_id")
	}

	protoVars := req.GetVariables()
	inputs := make([]domain.EnvVarInput, 0, len(protoVars))
	for _, v := range protoVars {
		if v == nil {
			continue
		}
		inputs = append(inputs, domain.EnvVarInput{
			Key:   v.GetKey(),
			Value: v.GetValue(),
		})
	}

	metas, err := s.secretsService.UpsertEnvVars(ctx, p, orgID, projectID, req.GetEnvironment(), inputs)
	if err != nil {
		return nil, mapDomainError(err)
	}

	keysChanged := make([]string, 0, len(metas))
	out := make([]*secretsv1.EnvVarMetadata, 0, len(metas))
	var envName string
	for i := range metas {
		envName = metas[i].Environment
		keysChanged = append(keysChanged, metas[i].Key)
		out = append(out, toEnvVarMetadataProto(&metas[i]))
	}

	// Emit audit event with variable keys only — never log secret values.
	s.emitAudit(ctx, p, orgID, projectID, pkgAudit.ActionProjectEnvVarsUpserted, map[string]any{
		"environment": envName,
		"keys":        keysChanged,
		"count":       len(keysChanged),
	})

	return &secretsv1.UpsertProjectEnvVarsResponse{
		Variables: out,
	}, nil
}

// ListProjectEnvVars lists masked metadata for a project's environment variables.
func (s *Server) ListProjectEnvVars(
	ctx context.Context,
	req *secretsv1.ListProjectEnvVarsRequest,
) (*secretsv1.ListProjectEnvVarsResponse, error) {
	p, orgID, err := s.parseOrgCall(ctx, req.GetCaller(), req.GetOrgId())
	if err != nil {
		return nil, err
	}
	projectID, err := uuid.Parse(strings.TrimSpace(req.GetProjectId()))
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid project_id")
	}

	metas, err := s.secretsService.ListEnvVars(ctx, p, orgID, projectID, req.GetEnvironment())
	if err != nil {
		return nil, mapDomainError(err)
	}

	out := make([]*secretsv1.EnvVarMetadata, 0, len(metas))
	for i := range metas {
		out = append(out, toEnvVarMetadataProto(&metas[i]))
	}
	return &secretsv1.ListProjectEnvVarsResponse{
		Variables: out,
	}, nil
}

// DeleteProjectEnvVar deletes an environment variable by key from a project.
func (s *Server) DeleteProjectEnvVar(
	ctx context.Context,
	req *secretsv1.DeleteProjectEnvVarRequest,
) (*secretsv1.DeleteProjectEnvVarResponse, error) {
	p, orgID, err := s.parseOrgCall(ctx, req.GetCaller(), req.GetOrgId())
	if err != nil {
		return nil, err
	}
	projectID, err := uuid.Parse(strings.TrimSpace(req.GetProjectId()))
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid project_id")
	}

	key := strings.TrimSpace(req.GetKey())
	env := req.GetEnvironment()
	if err := s.secretsService.DeleteEnvVar(ctx, p, orgID, projectID, env, key); err != nil {
		return nil, mapDomainError(err)
	}

	normEnv, _ := domain.NormalizeEnvironment(env)
	s.emitAudit(ctx, p, orgID, projectID, pkgAudit.ActionProjectEnvVarDeleted, map[string]any{
		"environment": normEnv,
		"key":         key,
	})

	return &secretsv1.DeleteProjectEnvVarResponse{
		Message: "environment variable deleted successfully",
	}, nil
}

// ResolveProjectSecrets implements SecretsInternalServiceServer for internal build/deployment runners.
// This service has NO HTTP annotations and is NEVER registered on the public API Gateway.
func (s *Server) ResolveProjectSecrets(
	ctx context.Context,
	req *secretsv1.ResolveProjectSecretsRequest,
) (*secretsv1.ResolveProjectSecretsResponse, error) {
	if s.serviceAuth.Enabled && !grpcauth.IsTrustedService(ctx) {
		return nil, status.Error(codes.Unauthenticated, "trusted service authentication required")
	}
	if s.secretsService == nil {
		return nil, status.Error(codes.Unimplemented, "secrets service not configured")
	}
	projectID, err := uuid.Parse(strings.TrimSpace(req.GetProjectId()))
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid project_id")
	}
	secretsMap, err := s.secretsService.ResolveProjectSecrets(ctx, projectID, req.GetEnvironment())
	if err != nil {
		return nil, mapDomainError(err)
	}
	return &secretsv1.ResolveProjectSecretsResponse{
		Secrets: secretsMap,
	}, nil
}

func (s *Server) parseOrgCall(ctx context.Context, c *authv1.CallerPrincipal, rawOrgID string) (domain.Principal, uuid.UUID, error) {
	if s.serviceAuth.Enabled && !grpcauth.IsTrustedService(ctx) {
		return domain.Principal{}, uuid.Nil, status.Error(codes.Unauthenticated, "caller principal rejected: untrusted service boundary")
	}
	if s.secretsService == nil {
		return domain.Principal{}, uuid.Nil, status.Error(codes.Unimplemented, "secrets service not configured")
	}
	if c == nil || strings.TrimSpace(c.GetUserId()) == "" {
		return domain.Principal{}, uuid.Nil, status.Error(codes.Unauthenticated, "authentication required: missing caller passport")
	}
	uid, err := uuid.Parse(strings.TrimSpace(c.GetUserId()))
	if err != nil {
		return domain.Principal{}, uuid.Nil, status.Error(codes.InvalidArgument, "invalid caller user_id")
	}
	orgID, err := uuid.Parse(strings.TrimSpace(rawOrgID))
	if err != nil {
		return domain.Principal{}, uuid.Nil, status.Error(codes.InvalidArgument, "invalid org_id")
	}

	p := domain.Principal{
		UserID:           uid,
		Kind:             c.GetKind(),
		TokenPermissions: c.GetTokenPermissions(),
	}
	if rawTokOrg := strings.TrimSpace(c.GetTokenOrgId()); rawTokOrg != "" {
		if oid, err := uuid.Parse(rawTokOrg); err == nil {
			p.TokenOrgID = &oid
		}
	}
	if rawSess := strings.TrimSpace(c.GetSessionId()); rawSess != "" {
		if sid, err := uuid.Parse(rawSess); err == nil {
			p.SessionID = &sid
		}
	}
	return p, orgID, nil
}

func (s *Server) emitAudit(ctx context.Context, p domain.Principal, orgID, projectID uuid.UUID, action pkgAudit.Action, meta map[string]any) {
	if s.auditEmitter == nil {
		return
	}

	actorType := pkgAudit.ActorTypeUser
	if p.Kind == pkgAudit.ActorTypeAPIToken {
		actorType = pkgAudit.ActorTypeAPIToken
	}

	clientCtx := pkgAudit.ExtractClientContext(ctx)
	actorID := p.UserID
	if err := s.auditEmitter.Emit(ctx, pkgAudit.Event{
		Service:        pkgAudit.ServiceSecrets,
		Action:         action.String(),
		Status:         pkgAudit.StatusSuccess,
		OrganizationID: &orgID,
		Actor: pkgAudit.Actor{
			UserID: &actorID,
			Type:   actorType,
		},
		Target: pkgAudit.Target{
			Type: pkgAudit.TargetTypeProject,
			ID:   projectID.String(),
		},
		ClientContext: clientCtx,
		Metadata:      meta,
	}); err != nil {
		log.Printf("secrets audit emit error (%s): %v", action, err)
	}
}

func toEnvVarMetadataProto(m *domain.EnvVarMetadata) *secretsv1.EnvVarMetadata {
	if m == nil {
		return nil
	}
	return &secretsv1.EnvVarMetadata{
		Id:          m.ID.String(),
		ProjectId:   m.ProjectID.String(),
		Environment: m.Environment,
		Key:         m.Key,
		MaskedValue: domain.MaskedSecretPlaceholder,
		HasValue:    true,
		DekVersion:  int32(m.DEKVersion),
		CreatedAt:   timestamppb.New(m.CreatedAt),
		UpdatedAt:   timestamppb.New(m.UpdatedAt),
	}
}

func mapDomainError(err error) error {
	switch {
	case errors.Is(err, domain.ErrForbidden):
		return status.Error(codes.PermissionDenied, "permission denied")
	case errors.Is(err, domain.ErrProjectNotFound):
		return status.Error(codes.NotFound, "project not found")
	case errors.Is(err, domain.ErrEnvVarNotFound):
		return status.Error(codes.NotFound, "environment variable not found")
	case errors.Is(err, domain.ErrMasterKeyNotConfigured):
		return status.Error(codes.FailedPrecondition, err.Error())
	case errors.Is(err, domain.ErrInvalidEnvVarKey),
		errors.Is(err, domain.ErrReservedEnvVarKey),
		errors.Is(err, domain.ErrEnvVarValueTooLarge),
		errors.Is(err, domain.ErrDuplicateEnvVarKey),
		errors.Is(err, domain.ErrEnvVarBatchLimit),
		errors.Is(err, domain.ErrInvalidEnvironment):
		return status.Error(codes.InvalidArgument, err.Error())
	default:
		log.Printf("secrets internal error: %v", err)
		return status.Error(codes.Internal, "internal server error")
	}
}
