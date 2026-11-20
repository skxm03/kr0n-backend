package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	authv1 "github.com/skxm03/kr0n-backend/control-plane/gen/auth/v1"
	"github.com/skxm03/kr0n-backend/control-plane/internal/auth/oauth"
	"github.com/skxm03/kr0n-backend/control-plane/internal/auth/repository"
)

func mapOrgError(err error) error {
	switch {
	case errors.Is(err, repository.ErrForbidden):
		return status.Error(codes.PermissionDenied, err.Error())
	case errors.Is(err, repository.ErrOrgNotFound),
		errors.Is(err, repository.ErrMemberNotFound),
		errors.Is(err, repository.ErrInviteNotFound),
		errors.Is(err, repository.ErrTokenNotFound),
		errors.Is(err, repository.ErrUserNotFound),
		errors.Is(err, repository.ErrInstallationNotFound):
		return status.Error(codes.NotFound, err.Error())
	case errors.Is(err, repository.ErrSlugAlreadyExists),
		errors.Is(err, repository.ErrMemberAlreadyExists),
		errors.Is(err, repository.ErrInstallationAlreadyLinked):
		return status.Error(codes.AlreadyExists, err.Error())
	case errors.Is(err, repository.ErrLastOwner),
		errors.Is(err, oauth.ErrGitHubAppNotConfigured):
		return status.Error(codes.FailedPrecondition, err.Error())
	case errors.Is(err, repository.ErrInvalidOrg),
		errors.Is(err, repository.ErrInvalidRole),
		errors.Is(err, repository.ErrInvalidInviteToken),
		errors.Is(err, repository.ErrInvalidAPIToken),
		errors.Is(err, repository.ErrInvalidEmail),
		errors.Is(err, oauth.ErrInvalidInstallationState):
		return status.Error(codes.InvalidArgument, err.Error())
	case errors.Is(err, oauth.ErrGitHubAppAPI):
		return status.Error(codes.Unavailable, err.Error())
	case errors.Is(err, repository.ErrUserNotActive):
		return status.Error(codes.PermissionDenied, err.Error())
	default:
		log.Printf("internal org service error: %v", err)
		return status.Error(codes.Internal, "internal server error")
	}
}

func toOrgProto(o *repository.Organization) *authv1.OrganizationResponse {
	return &authv1.OrganizationResponse{
		Id:        o.ID.String(),
		Name:      o.Name,
		Slug:      o.Slug,
		RoleId:    o.RoleID,
		CreatedAt: timestamppb.New(o.CreatedAt),
		UpdatedAt: timestamppb.New(o.UpdatedAt),
	}
}

func toAPITokenProto(t *repository.APIToken) *authv1.APITokenInfo {
	info := &authv1.APITokenInfo{
		Id:              t.ID.String(),
		OrgId:           t.OrganizationID.String(),
		CreatedByUserId: t.CreatedByUserID.String(),
		Name:            t.Name,
		TokenPrefix:     t.TokenPrefix,
		Permissions:     t.Permissions,
		CreatedAt:       timestamppb.New(t.CreatedAt),
	}
	if t.ExpiresAt != nil {
		info.ExpiresAt = timestamppb.New(*t.ExpiresAt)
	}
	if t.LastUsedAt != nil {
		info.LastUsedAt = timestamppb.New(*t.LastUsedAt)
	}
	return info
}

// CheckPermission evaluates whether a caller holds a permission in an organization.
func (s *Server) CheckPermission(ctx context.Context, req *authv1.CheckPermissionRequest) (*authv1.CheckPermissionResponse, error) {
	p, err := s.parseCallerPrincipal(ctx, req.GetCaller())
	if err != nil {
		return nil, err
	}
	if s.orgService == nil {
		return nil, status.Error(codes.Unimplemented, "org service not configured")
	}
	orgID, err := uuid.Parse(strings.TrimSpace(req.GetOrgId()))
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid org_id")
	}
	allowed, err := s.orgService.Can(ctx, p, orgID, strings.TrimSpace(req.GetPermission()))
	if err != nil {
		return nil, mapOrgError(err)
	}
	return &authv1.CheckPermissionResponse{Allowed: allowed}, nil
}

// ListRoles returns all RBAC roles and their granted permissions.
func (s *Server) ListRoles(ctx context.Context, req *authv1.ListRolesRequest) (*authv1.ListRolesResponse, error) {
	if s.serviceAuth.Enabled && !IsTrustedService(ctx) {
		return nil, status.Error(codes.Unauthenticated, "trusted service authentication required")
	}
	if s.orgService == nil {
		return nil, status.Error(codes.Unimplemented, "org service not configured")
	}
	roles, err := s.orgService.ListRoles(ctx)
	if err != nil {
		return nil, mapOrgError(err)
	}
	out := make([]*authv1.RoleInfo, 0, len(roles))
	for _, r := range roles {
		out = append(out, &authv1.RoleInfo{
			Id:          r.ID,
			Name:        r.Name,
			Description: r.Description,
			Permissions: r.Permissions,
		})
	}
	return &authv1.ListRolesResponse{Roles: out}, nil
}

// CreateOrganization creates an organization with the caller as owner.
func (s *Server) CreateOrganization(ctx context.Context, req *authv1.CreateOrganizationRequest) (*authv1.CreateOrganizationResponse, error) {
	if s.serviceAuth.Enabled && !IsTrustedService(ctx) {
		return nil, status.Error(codes.Unauthenticated, "trusted service authentication required")
	}
	if s.orgService == nil {
		return nil, status.Error(codes.Unimplemented, "org service not configured")
	}
	p, err := s.ParseCallerPrincipal(ctx, req.GetCaller())
	if err != nil {
		return nil, err
	}
	o, err := s.orgService.CreateOrg(ctx, p.UserID, req.GetName(), req.GetSlug())
	if err != nil {
		return nil, mapOrgError(err)
	}
	oid := o.ID
	s.recordAudit(ctx, repository.AuditEvent{
		OrganizationID: &oid,
		ActorUserID:    &p.UserID,
		ActorType:      actorTypeFromPrincipal(p),
		Action:         "org.created",
		ResourceType:   "organization",
		ResourceID:     o.ID.String(),
		Metadata:       map[string]any{"slug": o.Slug, "name": o.Name},
	})
	return &authv1.CreateOrganizationResponse{
		Id:        o.ID.String(),
		Name:      o.Name,
		Slug:      o.Slug,
		RoleId:    o.RoleID,
		CreatedAt: timestamppb.New(o.CreatedAt),
		UpdatedAt: timestamppb.New(o.UpdatedAt),
	}, nil
}

// ListOrganizations lists all organizations the user belongs to.
func (s *Server) ListOrganizations(ctx context.Context, req *authv1.ListOrganizationsRequest) (*authv1.ListOrganizationsResponse, error) {
	if s.serviceAuth.Enabled && !IsTrustedService(ctx) {
		return nil, status.Error(codes.Unauthenticated, "trusted service authentication required")
	}
	if s.orgService == nil {
		return nil, status.Error(codes.Unimplemented, "org service not configured")
	}
	p, err := s.ParseCallerPrincipal(ctx, req.GetCaller())
	if err != nil {
		return nil, err
	}
	orgs, err := s.orgService.ListUserOrgs(ctx, p.UserID)
	if err != nil {
		return nil, mapOrgError(err)
	}
	out := make([]*authv1.OrganizationResponse, 0, len(orgs))
	for i := range orgs {
		out = append(out, toOrgProto(&orgs[i]))
	}
	return &authv1.ListOrganizationsResponse{Organizations: out}, nil
}

// GetOrganization returns an organization by ID.
func (s *Server) GetOrganization(ctx context.Context, req *authv1.GetOrganizationRequest) (*authv1.GetOrganizationResponse, error) {
	p, err := s.parseCallerPrincipal(ctx, req.GetCaller())
	if err != nil {
		return nil, err
	}
	if s.orgService == nil {
		return nil, status.Error(codes.Unimplemented, "org service not configured")
	}
	orgID, err := uuid.Parse(strings.TrimSpace(req.GetOrgId()))
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid org_id")
	}
	o, err := s.orgService.GetOrg(ctx, p, orgID)
	if err != nil {
		return nil, mapOrgError(err)
	}
	return &authv1.GetOrganizationResponse{
		Id:        o.ID.String(),
		Name:      o.Name,
		Slug:      o.Slug,
		RoleId:    o.RoleID,
		CreatedAt: timestamppb.New(o.CreatedAt),
		UpdatedAt: timestamppb.New(o.UpdatedAt),
	}, nil
}

// UpdateOrganization updates an organization's name.
func (s *Server) UpdateOrganization(ctx context.Context, req *authv1.UpdateOrganizationRequest) (*authv1.UpdateOrganizationResponse, error) {
	p, err := s.parseCallerPrincipal(ctx, req.GetCaller())
	if err != nil {
		return nil, err
	}
	if s.orgService == nil {
		return nil, status.Error(codes.Unimplemented, "org service not configured")
	}
	orgID, err := uuid.Parse(strings.TrimSpace(req.GetOrgId()))
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid org_id")
	}
	o, err := s.orgService.UpdateOrg(ctx, p, orgID, req.GetName())
	if err != nil {
		return nil, mapOrgError(err)
	}
	actorID := p.UserID
	s.recordAudit(ctx, repository.AuditEvent{
		OrganizationID: &orgID,
		ActorUserID:    &actorID,
		ActorType:      actorTypeFromPrincipal(p),
		Action:         "org.updated",
		ResourceType:   "organization",
		ResourceID:     orgID.String(),
		Metadata:       map[string]any{"name": o.Name},
	})
	return &authv1.UpdateOrganizationResponse{
		Id:        o.ID.String(),
		Name:      o.Name,
		Slug:      o.Slug,
		RoleId:    o.RoleID,
		CreatedAt: timestamppb.New(o.CreatedAt),
		UpdatedAt: timestamppb.New(o.UpdatedAt),
	}, nil
}

// DeleteOrganization deletes an organization.
func (s *Server) DeleteOrganization(ctx context.Context, req *authv1.DeleteOrganizationRequest) (*authv1.DeleteOrganizationResponse, error) {
	p, err := s.parseCallerPrincipal(ctx, req.GetCaller())
	if err != nil {
		return nil, err
	}
	if s.orgService == nil {
		return nil, status.Error(codes.Unimplemented, "org service not configured")
	}
	orgID, err := uuid.Parse(strings.TrimSpace(req.GetOrgId()))
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid org_id")
	}
	if err := s.orgService.DeleteOrg(ctx, p, orgID); err != nil {
		return nil, mapOrgError(err)
	}
	actorID := p.UserID
	s.recordAudit(ctx, repository.AuditEvent{
		ActorUserID:  &actorID,
		ActorType:    actorTypeFromPrincipal(p),
		Action:       "org.deleted",
		ResourceType: "organization",
		ResourceID:   orgID.String(),
		Metadata:     map[string]any{"deleted_org_id": orgID.String()},
	})
	return &authv1.DeleteOrganizationResponse{Message: "organization deleted successfully"}, nil
}

// ListMembers lists members of an organization.
func (s *Server) ListMembers(ctx context.Context, req *authv1.ListMembersRequest) (*authv1.ListMembersResponse, error) {
	p, err := s.parseCallerPrincipal(ctx, req.GetCaller())
	if err != nil {
		return nil, err
	}
	if s.orgService == nil {
		return nil, status.Error(codes.Unimplemented, "org service not configured")
	}
	orgID, err := uuid.Parse(strings.TrimSpace(req.GetOrgId()))
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid org_id")
	}
	members, err := s.orgService.ListMembers(ctx, p, orgID)
	if err != nil {
		return nil, mapOrgError(err)
	}
	out := make([]*authv1.MemberInfo, 0, len(members))
	for _, m := range members {
		out = append(out, &authv1.MemberInfo{
			UserId:      m.UserID.String(),
			Email:       m.Email,
			DisplayName: m.DisplayName,
			RoleId:      m.RoleID,
			CreatedAt:   timestamppb.New(m.CreatedAt),
		})
	}
	return &authv1.ListMembersResponse{Members: out}, nil
}

// AddMember adds an existing user by email to an organization.
func (s *Server) AddMember(ctx context.Context, req *authv1.AddMemberRequest) (*authv1.AddMemberResponse, error) {
	p, err := s.parseCallerPrincipal(ctx, req.GetCaller())
	if err != nil {
		return nil, err
	}
	if s.orgService == nil {
		return nil, status.Error(codes.Unimplemented, "org service not configured")
	}
	orgID, err := uuid.Parse(strings.TrimSpace(req.GetOrgId()))
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid org_id")
	}
	m, err := s.orgService.AddMember(ctx, p, orgID, req.GetEmail(), req.GetRoleId())
	if err != nil {
		return nil, mapOrgError(err)
	}
	actorID := p.UserID
	s.recordAudit(ctx, repository.AuditEvent{
		OrganizationID: &orgID,
		ActorUserID:    &actorID,
		ActorType:      actorTypeFromPrincipal(p),
		Action:         "member.added",
		ResourceType:   "member",
		ResourceID:     m.UserID.String(),
		Metadata:       map[string]any{"email": m.Email, "role_id": m.RoleID},
	})
	return &authv1.AddMemberResponse{
		UserId:      m.UserID.String(),
		Email:       m.Email,
		DisplayName: m.DisplayName,
		RoleId:      m.RoleID,
		CreatedAt:   timestamppb.New(m.CreatedAt),
	}, nil
}

// UpdateMemberRole updates a member's role in an organization.
func (s *Server) UpdateMemberRole(ctx context.Context, req *authv1.UpdateMemberRoleRequest) (*authv1.UpdateMemberRoleResponse, error) {
	p, err := s.parseCallerPrincipal(ctx, req.GetCaller())
	if err != nil {
		return nil, err
	}
	if s.orgService == nil {
		return nil, status.Error(codes.Unimplemented, "org service not configured")
	}
	orgID, err := uuid.Parse(strings.TrimSpace(req.GetOrgId()))
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid org_id")
	}
	targetID, err := uuid.Parse(strings.TrimSpace(req.GetTargetUserId()))
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid target_user_id")
	}
	if err := s.orgService.UpdateMemberRole(ctx, p, orgID, targetID, req.GetRoleId()); err != nil {
		return nil, mapOrgError(err)
	}
	actorID := p.UserID
	s.recordAudit(ctx, repository.AuditEvent{
		OrganizationID: &orgID,
		ActorUserID:    &actorID,
		ActorType:      actorTypeFromPrincipal(p),
		Action:         "member.role_updated",
		ResourceType:   "member",
		ResourceID:     targetID.String(),
		Metadata:       map[string]any{"role_id": strings.ToLower(strings.TrimSpace(req.GetRoleId()))},
	})
	return &authv1.UpdateMemberRoleResponse{Message: "member role updated successfully"}, nil
}

// RemoveMember removes a member from an organization.
func (s *Server) RemoveMember(ctx context.Context, req *authv1.RemoveMemberRequest) (*authv1.RemoveMemberResponse, error) {
	p, err := s.parseCallerPrincipal(ctx, req.GetCaller())
	if err != nil {
		return nil, err
	}
	if s.orgService == nil {
		return nil, status.Error(codes.Unimplemented, "org service not configured")
	}
	orgID, err := uuid.Parse(strings.TrimSpace(req.GetOrgId()))
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid org_id")
	}
	targetID, err := uuid.Parse(strings.TrimSpace(req.GetTargetUserId()))
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid target_user_id")
	}
	if err := s.orgService.RemoveMember(ctx, p, orgID, targetID); err != nil {
		return nil, mapOrgError(err)
	}
	actorID := p.UserID
	s.recordAudit(ctx, repository.AuditEvent{
		OrganizationID: &orgID,
		ActorUserID:    &actorID,
		ActorType:      actorTypeFromPrincipal(p),
		Action:         "member.removed",
		ResourceType:   "member",
		ResourceID:     targetID.String(),
	})
	return &authv1.RemoveMemberResponse{Message: "member removed successfully"}, nil
}

// CreateInvite creates an organization invitation token.
func (s *Server) CreateInvite(ctx context.Context, req *authv1.CreateInviteRequest) (*authv1.CreateInviteResponse, error) {
	p, err := s.parseCallerPrincipal(ctx, req.GetCaller())
	if err != nil {
		return nil, err
	}
	if s.orgService == nil {
		return nil, status.Error(codes.Unimplemented, "org service not configured")
	}
	orgID, err := uuid.Parse(strings.TrimSpace(req.GetOrgId()))
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid org_id")
	}
	inv, rawToken, err := s.orgService.CreateInvite(ctx, p, orgID, req.GetEmail(), req.GetRoleId())
	if err != nil {
		return nil, mapOrgError(err)
	}
	actorID := p.UserID
	s.recordAudit(ctx, repository.AuditEvent{
		OrganizationID: &orgID,
		ActorUserID:    &actorID,
		ActorType:      actorTypeFromPrincipal(p),
		Action:         "invite.created",
		ResourceType:   "invite",
		ResourceID:     inv.ID.String(),
		Metadata:       map[string]any{"email": inv.Email, "role_id": inv.RoleID},
	})
	return &authv1.CreateInviteResponse{
		Id:        inv.ID.String(),
		OrgId:     inv.OrganizationID.String(),
		Email:     inv.Email,
		RoleId:    inv.RoleID,
		Token:     rawToken,
		ExpiresAt: timestamppb.New(inv.ExpiresAt),
		CreatedAt: timestamppb.New(inv.CreatedAt),
	}, nil
}

// AcceptInvite accepts an organization invitation token.
func (s *Server) AcceptInvite(ctx context.Context, req *authv1.AcceptInviteRequest) (*authv1.AcceptInviteResponse, error) {
	if s.serviceAuth.Enabled && !IsTrustedService(ctx) {
		return nil, status.Error(codes.Unauthenticated, "trusted service authentication required")
	}
	if s.orgService == nil {
		return nil, status.Error(codes.Unimplemented, "org service not configured")
	}
	p, err := s.ParseCallerPrincipal(ctx, req.GetCaller())
	if err != nil {
		return nil, err
	}
	o, err := s.orgService.AcceptInvite(ctx, p.UserID, req.GetToken())
	if err != nil {
		return nil, mapOrgError(err)
	}
	oid := o.ID
	s.recordAudit(ctx, repository.AuditEvent{
		OrganizationID: &oid,
		ActorUserID:    &p.UserID,
		ActorType:      actorTypeFromPrincipal(p),
		Action:         "invite.accepted",
		ResourceType:   "member",
		ResourceID:     p.UserID.String(),
		Metadata:       map[string]any{"role_id": o.RoleID},
	})
	return &authv1.AcceptInviteResponse{
		Id:        o.ID.String(),
		Name:      o.Name,
		Slug:      o.Slug,
		RoleId:    o.RoleID,
		CreatedAt: timestamppb.New(o.CreatedAt),
		UpdatedAt: timestamppb.New(o.UpdatedAt),
	}, nil
}

// RevokeInvite revokes a pending organization invitation.
func (s *Server) RevokeInvite(ctx context.Context, req *authv1.RevokeInviteRequest) (*authv1.RevokeInviteResponse, error) {
	p, err := s.parseCallerPrincipal(ctx, req.GetCaller())
	if err != nil {
		return nil, err
	}
	if s.orgService == nil {
		return nil, status.Error(codes.Unimplemented, "org service not configured")
	}
	orgID, err := uuid.Parse(strings.TrimSpace(req.GetOrgId()))
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid org_id")
	}
	inviteID, err := uuid.Parse(strings.TrimSpace(req.GetInviteId()))
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid invite_id")
	}
	if err := s.orgService.RevokeInvite(ctx, p, orgID, inviteID); err != nil {
		return nil, mapOrgError(err)
	}
	actorID := p.UserID
	s.recordAudit(ctx, repository.AuditEvent{
		OrganizationID: &orgID,
		ActorUserID:    &actorID,
		ActorType:      actorTypeFromPrincipal(p),
		Action:         "invite.revoked",
		ResourceType:   "invite",
		ResourceID:     inviteID.String(),
	})
	return &authv1.RevokeInviteResponse{Message: "invite revoked successfully"}, nil
}

// CreateAPIToken creates an org-scoped API token (`kr0n_pat_...`).
func (s *Server) CreateAPIToken(ctx context.Context, req *authv1.CreateAPITokenRequest) (*authv1.CreateAPITokenResponse, error) {
	p, err := s.parseCallerPrincipal(ctx, req.GetCaller())
	if err != nil {
		return nil, err
	}
	if s.orgService == nil {
		return nil, status.Error(codes.Unimplemented, "org service not configured")
	}
	orgID, err := uuid.Parse(strings.TrimSpace(req.GetOrgId()))
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid org_id")
	}
	tok, secret, err := s.orgService.CreateAPIToken(ctx, p, orgID, req.GetName(), req.GetPermissions(), req.GetExpiresInSeconds())
	if err != nil {
		return nil, mapOrgError(err)
	}
	actorID := p.UserID
	s.recordAudit(ctx, repository.AuditEvent{
		OrganizationID: &orgID,
		ActorUserID:    &actorID,
		ActorType:      actorTypeFromPrincipal(p),
		Action:         "apitoken.created",
		ResourceType:   "api_token",
		ResourceID:     tok.ID.String(),
		Metadata:       map[string]any{"name": tok.Name, "token_prefix": tok.TokenPrefix, "permissions": tok.Permissions},
	})
	return &authv1.CreateAPITokenResponse{
		Token:  toAPITokenProto(tok),
		Secret: secret,
	}, nil
}

// ListAPITokens lists active API tokens for an organization.
func (s *Server) ListAPITokens(ctx context.Context, req *authv1.ListAPITokensRequest) (*authv1.ListAPITokensResponse, error) {
	p, err := s.parseCallerPrincipal(ctx, req.GetCaller())
	if err != nil {
		return nil, err
	}
	if s.orgService == nil {
		return nil, status.Error(codes.Unimplemented, "org service not configured")
	}
	orgID, err := uuid.Parse(strings.TrimSpace(req.GetOrgId()))
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid org_id")
	}
	tokens, err := s.orgService.ListAPITokens(ctx, p, orgID)
	if err != nil {
		return nil, mapOrgError(err)
	}
	out := make([]*authv1.APITokenInfo, 0, len(tokens))
	for i := range tokens {
		out = append(out, toAPITokenProto(&tokens[i]))
	}
	return &authv1.ListAPITokensResponse{Tokens: out}, nil
}

// RevokeAPIToken revokes an organization API token.
func (s *Server) RevokeAPIToken(ctx context.Context, req *authv1.RevokeAPITokenRequest) (*authv1.RevokeAPITokenResponse, error) {
	p, err := s.parseCallerPrincipal(ctx, req.GetCaller())
	if err != nil {
		return nil, err
	}
	if s.orgService == nil {
		return nil, status.Error(codes.Unimplemented, "org service not configured")
	}
	orgID, err := uuid.Parse(strings.TrimSpace(req.GetOrgId()))
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid org_id")
	}
	tokenID, err := uuid.Parse(strings.TrimSpace(req.GetTokenId()))
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid token_id")
	}
	if err := s.orgService.RevokeAPIToken(ctx, p, orgID, tokenID); err != nil {
		return nil, mapOrgError(err)
	}
	actorID := p.UserID
	s.recordAudit(ctx, repository.AuditEvent{
		OrganizationID: &orgID,
		ActorUserID:    &actorID,
		ActorType:      actorTypeFromPrincipal(p),
		Action:         "apitoken.revoked",
		ResourceType:   "api_token",
		ResourceID:     tokenID.String(),
	})
	return &authv1.RevokeAPITokenResponse{Message: "token revoked successfully"}, nil
}

// ValidateAPIToken validates a raw `kr0n_pat_...` token and returns its org scope and permissions.
func (s *Server) ValidateAPIToken(ctx context.Context, req *authv1.ValidateAPITokenRequest) (*authv1.ValidateAPITokenResponse, error) {
	if s.serviceAuth.Enabled && !IsTrustedService(ctx) {
		return nil, status.Error(codes.Unauthenticated, "trusted service authentication required")
	}
	if s.orgService == nil {
		return nil, status.Error(codes.Unimplemented, "org service not configured")
	}
	tok, err := s.orgService.ValidateAPIToken(ctx, req.GetToken())
	if err != nil {
		if errors.Is(err, repository.ErrInvalidAPIToken) {
			return nil, status.Error(codes.Unauthenticated, "invalid api token")
		}
		return nil, mapOrgError(err)
	}
	return &authv1.ValidateAPITokenResponse{
		TokenId:     tok.ID.String(),
		OrgId:       tok.OrganizationID.String(),
		UserId:      tok.CreatedByUserID.String(),
		Permissions: tok.Permissions,
	}, nil
}

// ListAuditEvents lists append-only audit events for an organization, gated by `audit:read`.
func (s *Server) ListAuditEvents(ctx context.Context, req *authv1.ListAuditEventsRequest) (*authv1.ListAuditEventsResponse, error) {
	p, err := s.parseCallerPrincipal(ctx, req.GetCaller())
	if err != nil {
		return nil, err
	}
	if s.orgService == nil || s.auditService == nil {
		return nil, status.Error(codes.Unimplemented, "audit service not configured")
	}
	orgID, err := uuid.Parse(strings.TrimSpace(req.GetOrgId()))
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid org_id")
	}
	allowed, err := s.orgService.Can(ctx, p, orgID, "audit:read")
	if err != nil {
		return nil, mapOrgError(err)
	}
	if !allowed {
		return nil, status.Error(codes.PermissionDenied, "permission denied")
	}
	events, err := s.auditService.ListByOrg(ctx, orgID, req.GetAction(), int(req.GetLimit()), int(req.GetOffset()))
	if err != nil {
		log.Printf("internal list audit events error: %v", err)
		return nil, status.Error(codes.Internal, "internal server error")
	}
	out := make([]*authv1.AuditEventInfo, 0, len(events))
	for _, ev := range events {
		info := &authv1.AuditEventInfo{
			Id:           ev.ID.String(),
			OrgId:        orgID.String(),
			ActorType:    ev.ActorType,
			Action:       ev.Action,
			ResourceType: ev.ResourceType,
			ResourceId:   ev.ResourceID,
			CreatedAt:    timestamppb.New(ev.CreatedAt),
		}
		if ev.ActorUserID != nil {
			info.ActorUserId = ev.ActorUserID.String()
		}
		if ev.IPAddress != nil {
			info.IpAddress = ev.IPAddress.String()
		}
		if ev.UserAgent != nil {
			info.UserAgent = *ev.UserAgent
		}
		if len(ev.Metadata) > 0 {
			if b, err := json.Marshal(ev.Metadata); err == nil {
				info.MetadataJson = string(b)
			}
		} else {
			info.MetadataJson = "{}"
		}
		out = append(out, info)
	}
	return &authv1.ListAuditEventsResponse{Events: out}, nil
}

func toGitHubInstallationProto(inst *repository.GitHubInstallation) *authv1.GitHubInstallationInfo {
	return &authv1.GitHubInstallationInfo{
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

func (s *Server) parseOrgCall(ctx context.Context, c *authv1.CallerPrincipal, rawOrgID string) (repository.Principal, uuid.UUID, error) {
	p, err := s.ParseCallerPrincipal(ctx, c)
	if err != nil {
		return repository.Principal{}, uuid.Nil, err
	}
	if s.orgService == nil {
		return repository.Principal{}, uuid.Nil, status.Error(codes.Unimplemented, "org service not configured")
	}
	orgID, err := uuid.Parse(strings.TrimSpace(rawOrgID))
	if err != nil {
		return repository.Principal{}, uuid.Nil, status.Error(codes.InvalidArgument, "invalid org_id")
	}
	return p, orgID, nil
}

// StartGitHubInstallation generates a signed installation state token and GitHub App installation URL.
func (s *Server) StartGitHubInstallation(ctx context.Context, req *authv1.StartGitHubInstallationRequest) (*authv1.StartGitHubInstallationResponse, error) {
	p, orgID, err := s.parseOrgCall(ctx, req.GetCaller(), req.GetOrgId())
	if err != nil {
		return nil, err
	}
	installURL, state, err := s.orgService.StartGitHubInstallation(ctx, p, orgID)
	if err != nil {
		return nil, mapOrgError(err)
	}
	return &authv1.StartGitHubInstallationResponse{
		InstallUrl: installURL,
		State:      state,
	}, nil
}

// CompleteGitHubInstallation verifies the installation state and links the GitHub App installation to the organization.
func (s *Server) CompleteGitHubInstallation(ctx context.Context, req *authv1.CompleteGitHubInstallationRequest) (*authv1.CompleteGitHubInstallationResponse, error) {
	p, orgID, err := s.parseOrgCall(ctx, req.GetCaller(), req.GetOrgId())
	if err != nil {
		return nil, err
	}
	inst, err := s.orgService.CompleteGitHubInstallation(ctx, p, orgID, req.GetInstallationId(), req.GetState())
	if err != nil {
		return nil, mapOrgError(err)
	}
	actorID := p.UserID
	s.recordAudit(ctx, repository.AuditEvent{
		OrganizationID: &orgID,
		ActorUserID:    &actorID,
		ActorType:      actorTypeFromPrincipal(p),
		Action:         "github.installation_connected",
		ResourceType:   "github_installation",
		ResourceID:     strconv.FormatInt(inst.InstallationID, 10),
		Metadata: map[string]any{
			"installation_id": inst.InstallationID,
			"account_login":   inst.AccountLogin,
			"account_type":    inst.AccountType,
		},
	})
	return &authv1.CompleteGitHubInstallationResponse{
		Installation: toGitHubInstallationProto(inst),
	}, nil
}

// ListGitHubInstallations lists GitHub App installations linked to the organization.
func (s *Server) ListGitHubInstallations(ctx context.Context, req *authv1.ListGitHubInstallationsRequest) (*authv1.ListGitHubInstallationsResponse, error) {
	p, orgID, err := s.parseOrgCall(ctx, req.GetCaller(), req.GetOrgId())
	if err != nil {
		return nil, err
	}
	installations, err := s.orgService.ListGitHubInstallations(ctx, p, orgID)
	if err != nil {
		return nil, mapOrgError(err)
	}
	out := make([]*authv1.GitHubInstallationInfo, 0, len(installations))
	for i := range installations {
		out = append(out, toGitHubInstallationProto(&installations[i]))
	}
	return &authv1.ListGitHubInstallationsResponse{Installations: out}, nil
}

// DisconnectGitHubInstallation unlinks a GitHub App installation from the organization.
func (s *Server) DisconnectGitHubInstallation(ctx context.Context, req *authv1.DisconnectGitHubInstallationRequest) (*authv1.DisconnectGitHubInstallationResponse, error) {
	p, orgID, err := s.parseOrgCall(ctx, req.GetCaller(), req.GetOrgId())
	if err != nil {
		return nil, err
	}
	if err := s.orgService.DisconnectGitHubInstallation(ctx, p, orgID, req.GetInstallationId()); err != nil {
		return nil, mapOrgError(err)
	}
	actorID := p.UserID
	s.recordAudit(ctx, repository.AuditEvent{
		OrganizationID: &orgID,
		ActorUserID:    &actorID,
		ActorType:      actorTypeFromPrincipal(p),
		Action:         "github.installation_disconnected",
		ResourceType:   "github_installation",
		ResourceID:     strconv.FormatInt(req.GetInstallationId(), 10),
		Metadata: map[string]any{
			"installation_id": req.GetInstallationId(),
		},
	})
	return &authv1.DisconnectGitHubInstallationResponse{
		Message: "github installation disconnected successfully",
	}, nil
}

// GetGitHubInstallationToken exchanges organization permissions and caller principal for a scoped GitHub App installation token.
func (s *Server) GetGitHubInstallationToken(ctx context.Context, req *authv1.GetGitHubInstallationTokenRequest) (*authv1.GetGitHubInstallationTokenResponse, error) {
	p, orgID, err := s.parseOrgCall(ctx, req.GetCaller(), req.GetOrgId())
	if err != nil {
		return nil, err
	}
	tok, instID, exp, err := s.orgService.GetInstallationToken(ctx, p, orgID, req.GetInstallationId())
	if err != nil {
		return nil, mapOrgError(err)
	}
	return &authv1.GetGitHubInstallationTokenResponse{
		Token:          tok,
		InstallationId: instID,
		ExpiresAtUnix:  exp.Unix(),
	}, nil
}

// HandleGitHubWebhook verifies and processes raw GitHub App webhook deliveries over gRPC.
func (s *Server) HandleGitHubWebhook(ctx context.Context, req *authv1.HandleGitHubWebhookRequest) (*authv1.HandleGitHubWebhookResponse, error) {
	if s.serviceAuth.Enabled && !IsTrustedService(ctx) {
		return nil, status.Error(codes.Unauthenticated, "trusted service authentication required")
	}
	if s.webhookHandler == nil {
		return nil, status.Error(codes.Unimplemented, "github webhook handler not configured")
	}

	httpCode, _, err := s.webhookHandler.Process(
		ctx,
		req.GetEventType(),
		req.GetDeliveryId(),
		req.GetSignatureHeader(),
		req.GetPayload(),
	)
	if err != nil {
		switch httpCode {
		case 401:
			return nil, status.Error(codes.Unauthenticated, err.Error())
		case 400:
			return nil, status.Error(codes.InvalidArgument, err.Error())
		case 413:
			return nil, status.Error(codes.ResourceExhausted, err.Error())
		default:
			return nil, status.Error(codes.Internal, "internal webhook processing error")
		}
	}

	respStatus := "received"
	if strings.EqualFold(strings.TrimSpace(req.GetEventType()), "ping") {
		respStatus = "pong"
	}
	return &authv1.HandleGitHubWebhookResponse{
		Status: respStatus,
	}, nil
}
