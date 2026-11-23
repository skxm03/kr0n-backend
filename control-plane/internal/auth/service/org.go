package service

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/skxm03/kr0n-backend/control-plane/internal/auth/domain"
	"github.com/skxm03/kr0n-backend/control-plane/internal/auth/repository"
	pkgAudit "github.com/skxm03/kr0n-backend/control-plane/pkg/audit"
	"github.com/skxm03/kr0n-backend/control-plane/pkg/authz"
)

var slugRegex = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*$`)

// OrgOption configures OrgService.
type OrgOption func(*OrgService)

// WithOrgOutboxNotifier wires an outbox notifier to OrgService.
func WithOrgOutboxNotifier(notifier OutboxNotifier) OrgOption {
	return func(s *OrgService) {
		s.notifier = notifier
	}
}

// WithOrgAuditRecorder wires an audit recorder to OrgService.
func WithOrgAuditRecorder(recorder AuditRecorder) OrgOption {
	return func(s *OrgService) {
		s.audit = recorder
	}
}

// OrgService orchestrates organizations, memberships, invites, RBAC checks, and API tokens.
type OrgService struct {
	repo     repository.OrgRepository
	notifier OutboxNotifier
	audit    AuditRecorder
}

// NewOrgService constructs an OrgService.
func NewOrgService(repo repository.OrgRepository, opts ...OrgOption) *OrgService {
	s := &OrgService{repo: repo}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// Can evaluates whether principal holds permission in orgID.
func (s *OrgService) Can(ctx context.Context, p domain.Principal, orgID uuid.UUID, permission string) (bool, error) {
	if p.UserID == uuid.Nil || orgID == uuid.Nil || permission == "" {
		return false, nil
	}
	if p.Kind == "api_token" {
		if p.TokenOrgID == nil || *p.TokenOrgID != orgID || !hasPermission(p.TokenPermissions, permission) {
			return false, nil
		}
	}

	_, perms, err := s.repo.RolePermissions(ctx, p.UserID, orgID)
	if err != nil {
		if errors.Is(err, domain.ErrMemberNotFound) {
			return false, nil
		}
		return false, err
	}
	return hasPermission(perms, permission), nil
}

func hasPermission(perms []string, permission string) bool {
	return authz.HasPermission(perms, permission)
}

func (s *OrgService) require(ctx context.Context, p domain.Principal, orgID uuid.UUID, permission string) error {
	allowed, err := s.Can(ctx, p, orgID, permission)
	if err != nil {
		return err
	}
	if !allowed {
		return domain.ErrForbidden
	}
	return nil
}

func validateRoleID(roleID string) bool {
	return roleID == "owner" || roleID == "admin" || roleID == "member"
}

// CreateOrg validates name and slug, then creates the organization with creatorUserID as owner.
func (s *OrgService) CreateOrg(ctx context.Context, creatorUserID uuid.UUID, name, slug string) (*domain.Organization, error) {
	name = strings.TrimSpace(name)
	slug = strings.ToLower(strings.TrimSpace(slug))
	if len(name) < 1 || len(name) > 100 || len(slug) < 2 || len(slug) > 63 || !slugRegex.MatchString(slug) {
		return nil, domain.ErrInvalidOrg
	}
	now := time.Now().UTC()
	o := &domain.Organization{
		ID:        uuid.New(),
		Name:      name,
		Slug:      slug,
		RoleID:    "owner",
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := s.repo.CreateOrg(ctx, o, creatorUserID); err != nil {
		return nil, err
	}
	s.recordAudit(ctx, domain.AuditEvent{
		OrganizationID: &o.ID,
		ActorUserID:    &creatorUserID,
		ActorType:      domain.ActorTypeUser,
		Action:         pkgAudit.ActionOrgCreated.String(),
		ResourceType:   pkgAudit.TargetTypeOrg,
		ResourceID:     o.ID.String(),
		Metadata:       map[string]any{"slug": o.Slug, "name": o.Name},
	})
	return o, nil
}

// ListUserOrgs returns all organizations the user belongs to.
func (s *OrgService) ListUserOrgs(ctx context.Context, userID uuid.UUID) ([]domain.Organization, error) {
	return s.repo.ListUserOrgs(ctx, userID)
}

// GetOrg returns an organization if the principal has org:read.
func (s *OrgService) GetOrg(ctx context.Context, p domain.Principal, orgID uuid.UUID) (*domain.Organization, error) {
	if err := s.require(ctx, p, orgID, "org:read"); err != nil {
		return nil, err
	}
	return s.repo.GetOrg(ctx, orgID)
}

// UpdateOrg updates an organization's display name if the principal has org:update.
func (s *OrgService) UpdateOrg(ctx context.Context, p domain.Principal, orgID uuid.UUID, name string) (*domain.Organization, error) {
	if err := s.require(ctx, p, orgID, "org:update"); err != nil {
		return nil, err
	}
	name = strings.TrimSpace(name)
	if len(name) < 1 || len(name) > 100 {
		return nil, domain.ErrInvalidOrg
	}
	updated, err := s.repo.UpdateOrg(ctx, orgID, name, time.Now().UTC())
	if err != nil {
		return nil, err
	}
	actorID := p.UserID
	s.recordAudit(ctx, domain.AuditEvent{
		OrganizationID: &orgID,
		ActorUserID:    &actorID,
		ActorType:      actorTypeFromPrincipal(p),
		Action:         pkgAudit.ActionOrgUpdated.String(),
		ResourceType:   pkgAudit.TargetTypeOrg,
		ResourceID:     orgID.String(),
		Metadata:       map[string]any{"name": updated.Name},
	})
	return updated, nil
}

// DeleteOrg deletes an organization if the principal has org:delete.
func (s *OrgService) DeleteOrg(ctx context.Context, p domain.Principal, orgID uuid.UUID) error {
	if err := s.require(ctx, p, orgID, "org:delete"); err != nil {
		return err
	}
	if err := s.repo.DeleteOrg(ctx, orgID); err != nil {
		return err
	}
	actorID := p.UserID
	s.recordAudit(ctx, domain.AuditEvent{
		OrganizationID: &orgID,
		ActorUserID:    &actorID,
		ActorType:      actorTypeFromPrincipal(p),
		Action:         pkgAudit.ActionOrgDeleted.String(),
		ResourceType:   pkgAudit.TargetTypeOrg,
		ResourceID:     orgID.String(),
	})
	return nil
}

// ListRoles returns all seeded RBAC roles and their permissions.
func (s *OrgService) ListRoles(ctx context.Context) ([]domain.Role, error) {
	return s.repo.ListRoles(ctx)
}

// ListMembers lists organization members if the principal has member:read.
func (s *OrgService) ListMembers(ctx context.Context, p domain.Principal, orgID uuid.UUID) ([]domain.Member, error) {
	if err := s.require(ctx, p, orgID, "member:read"); err != nil {
		return nil, err
	}
	return s.repo.ListMembers(ctx, orgID)
}

// AddMember adds an existing user by email to the organization if the principal has member:create.
func (s *OrgService) AddMember(ctx context.Context, p domain.Principal, orgID uuid.UUID, rawEmail, roleID string) (*domain.Member, error) {
	if err := s.require(ctx, p, orgID, "member:create"); err != nil {
		return nil, err
	}
	roleID = strings.ToLower(strings.TrimSpace(roleID))
	if !validateRoleID(roleID) {
		return nil, domain.ErrInvalidRole
	}
	email, err := domain.CanonicalizeEmail(rawEmail)
	if err != nil {
		return nil, err
	}
	m, err := s.repo.AddMemberByEmail(ctx, orgID, email, roleID, time.Now().UTC())
	if err != nil {
		return nil, err
	}
	actorID := p.UserID
	s.recordAudit(ctx, domain.AuditEvent{
		OrganizationID: &orgID,
		ActorUserID:    &actorID,
		ActorType:      actorTypeFromPrincipal(p),
		Action:         pkgAudit.ActionOrgMemberAdded.String(),
		ResourceType:   pkgAudit.TargetTypeOrgMember,
		ResourceID:     m.UserID.String(),
		Metadata:       map[string]any{"email": m.Email, "role_id": m.RoleID},
	})
	return m, nil
}

// UpdateMemberRole updates a member's role if the principal has member:update, enforcing the last-owner guard.
func (s *OrgService) UpdateMemberRole(ctx context.Context, p domain.Principal, orgID, targetUserID uuid.UUID, roleID string) error {
	if err := s.require(ctx, p, orgID, "member:update"); err != nil {
		return err
	}
	roleID = strings.ToLower(strings.TrimSpace(roleID))
	if !validateRoleID(roleID) {
		return domain.ErrInvalidRole
	}
	if err := s.repo.UpdateMemberRole(ctx, orgID, targetUserID, roleID, time.Now().UTC()); err != nil {
		return err
	}
	actorID := p.UserID
	s.recordAudit(ctx, domain.AuditEvent{
		OrganizationID: &orgID,
		ActorUserID:    &actorID,
		ActorType:      actorTypeFromPrincipal(p),
		Action:         pkgAudit.ActionOrgMemberRoleUpdated.String(),
		ResourceType:   pkgAudit.TargetTypeOrgMember,
		ResourceID:     targetUserID.String(),
		Metadata:       map[string]any{"role_id": roleID},
	})
	return nil
}

// RemoveMember removes a member from an organization if the principal has member:delete, enforcing the last-owner guard.
func (s *OrgService) RemoveMember(ctx context.Context, p domain.Principal, orgID, targetUserID uuid.UUID) error {
	if err := s.require(ctx, p, orgID, "member:delete"); err != nil {
		return err
	}
	if err := s.repo.RemoveMember(ctx, orgID, targetUserID); err != nil {
		return err
	}
	actorID := p.UserID
	s.recordAudit(ctx, domain.AuditEvent{
		OrganizationID: &orgID,
		ActorUserID:    &actorID,
		ActorType:      actorTypeFromPrincipal(p),
		Action:         pkgAudit.ActionOrgMemberRemoved.String(),
		ResourceType:   pkgAudit.TargetTypeOrgMember,
		ResourceID:     targetUserID.String(),
	})
	return nil
}

// CreateInvite creates an organization invite token if the principal has member:create.
func (s *OrgService) CreateInvite(ctx context.Context, p domain.Principal, orgID uuid.UUID, rawEmail, roleID string) (*domain.Invite, string, error) {
	if err := s.require(ctx, p, orgID, "member:create"); err != nil {
		return nil, "", err
	}
	roleID = strings.ToLower(strings.TrimSpace(roleID))
	if !validateRoleID(roleID) {
		return nil, "", domain.ErrInvalidRole
	}
	email, err := domain.CanonicalizeEmail(rawEmail)
	if err != nil {
		return nil, "", err
	}
	rawToken, err := domain.GenerateToken()
	if err != nil {
		return nil, "", err
	}
	now := time.Now().UTC()
	inv := &domain.Invite{
		ID:              uuid.New(),
		OrganizationID:  orgID,
		Email:           email,
		RoleID:          roleID,
		InvitedByUserID: p.UserID,
		TokenHash:       domain.HashToken(rawToken),
		ExpiresAt:       now.Add(7 * 24 * time.Hour),
		CreatedAt:       now,
	}

	orgName := "kr0n organization"
	if o, err := s.repo.GetOrg(ctx, orgID); err == nil && o != nil {
		orgName = o.Name
	}

	ev := domain.OrgInviteEvent{
		OrgID:    orgID,
		OrgName:  orgName,
		Email:    inv.Email,
		RoleID:   inv.RoleID,
		RawToken: rawToken,
	}

	if err := s.repo.CreateInvite(ctx, inv, ev); err != nil {
		return nil, "", err
	}

	actorID := p.UserID
	s.recordAudit(ctx, domain.AuditEvent{
		OrganizationID: &orgID,
		ActorUserID:    &actorID,
		ActorType:      actorTypeFromPrincipal(p),
		Action:         pkgAudit.ActionOrgMemberInvited.String(),
		ResourceType:   pkgAudit.TargetTypeOrgInvite,
		ResourceID:     inv.ID.String(),
		Metadata:       map[string]any{"email": inv.Email, "role_id": inv.RoleID},
	})

	if s.notifier != nil {
		s.notifier.Notify()
	}

	return inv, rawToken, nil
}

// AcceptInvite consumes an invite token and adds userID to the organization.
func (s *OrgService) AcceptInvite(ctx context.Context, userID uuid.UUID, rawToken string) (*domain.Organization, error) {
	rawToken = strings.TrimSpace(rawToken)
	if userID == uuid.Nil || rawToken == "" {
		return nil, domain.ErrInvalidInviteToken
	}
	org, err := s.repo.AcceptInvite(ctx, userID, domain.HashToken(rawToken), time.Now().UTC())
	if err != nil {
		return nil, err
	}
	s.recordAudit(ctx, domain.AuditEvent{
		OrganizationID: &org.ID,
		ActorUserID:    &userID,
		ActorType:      domain.ActorTypeUser,
		Action:         pkgAudit.ActionOrgInviteAccepted.String(),
		ResourceType:   pkgAudit.TargetTypeOrgInvite,
		ResourceID:     org.ID.String(),
		Metadata:       map[string]any{"org_name": org.Name, "org_slug": org.Slug},
	})
	return org, nil
}

// RevokeInvite revokes a pending organization invite if the principal has member:delete.
func (s *OrgService) RevokeInvite(ctx context.Context, p domain.Principal, orgID, inviteID uuid.UUID) error {
	if err := s.require(ctx, p, orgID, "member:delete"); err != nil {
		return err
	}
	if err := s.repo.RevokeInvite(ctx, orgID, inviteID, time.Now().UTC()); err != nil {
		return err
	}
	actorID := p.UserID
	s.recordAudit(ctx, domain.AuditEvent{
		OrganizationID: &orgID,
		ActorUserID:    &actorID,
		ActorType:      actorTypeFromPrincipal(p),
		Action:         pkgAudit.ActionOrgInviteRevoked.String(),
		ResourceType:   pkgAudit.TargetTypeOrgInvite,
		ResourceID:     inviteID.String(),
	})
	return nil
}

// CreateAPIToken issues an org-scoped API token (`kr0n_pat_...`) whose permissions must be a subset
// of the caller's effective permissions in the organization.
func (s *OrgService) CreateAPIToken(ctx context.Context, p domain.Principal, orgID uuid.UUID, name string, requestedPerms []string, expiresInSeconds int64) (*domain.APIToken, string, error) {
	if p.Kind == "api_token" {
		return nil, "", domain.ErrForbidden
	}
	if err := s.require(ctx, p, orgID, "apitoken:create"); err != nil {
		return nil, "", err
	}
	name = strings.TrimSpace(name)
	if len(name) < 1 || len(name) > 100 || len(requestedPerms) == 0 {
		return nil, "", domain.ErrInvalidAPIToken
	}

	for _, perm := range requestedPerms {
		ok, err := s.Can(ctx, p, orgID, perm)
		if err != nil {
			return nil, "", err
		}
		if !ok {
			return nil, "", domain.ErrForbidden
		}
	}

	rawToken, prefix, tokenHash, err := domain.GenerateAPIToken()
	if err != nil {
		return nil, "", err
	}
	now := time.Now().UTC()
	var expiresAt *time.Time
	if expiresInSeconds > 0 {
		exp := now.Add(time.Duration(expiresInSeconds) * time.Second)
		expiresAt = &exp
	}

	tok := &domain.APIToken{
		ID:              uuid.New(),
		OrganizationID:  orgID,
		CreatedByUserID: p.UserID,
		Name:            name,
		TokenPrefix:     prefix,
		TokenHash:       tokenHash,
		Permissions:     requestedPerms,
		ExpiresAt:       expiresAt,
		CreatedAt:       now,
	}
	if err := s.repo.CreateAPIToken(ctx, tok); err != nil {
		return nil, "", err
	}
	actorID := p.UserID
	s.recordAudit(ctx, domain.AuditEvent{
		OrganizationID: &orgID,
		ActorUserID:    &actorID,
		ActorType:      actorTypeFromPrincipal(p),
		Action:         pkgAudit.ActionAPITokenCreated.String(),
		ResourceType:   pkgAudit.TargetTypeAPIToken,
		ResourceID:     tok.ID.String(),
		Metadata:       map[string]any{"name": tok.Name, "permissions": tok.Permissions},
	})
	return tok, rawToken, nil
}

// ListAPITokens lists non-revoked API tokens for an organization if the principal has apitoken:read.
func (s *OrgService) ListAPITokens(ctx context.Context, p domain.Principal, orgID uuid.UUID) ([]domain.APIToken, error) {
	if err := s.require(ctx, p, orgID, "apitoken:read"); err != nil {
		return nil, err
	}
	return s.repo.ListAPITokens(ctx, orgID)
}

// RevokeAPIToken revokes an API token if the principal has apitoken:delete.
func (s *OrgService) RevokeAPIToken(ctx context.Context, p domain.Principal, orgID, tokenID uuid.UUID) error {
	if err := s.require(ctx, p, orgID, "apitoken:delete"); err != nil {
		return err
	}
	if err := s.repo.RevokeAPIToken(ctx, orgID, tokenID, time.Now().UTC()); err != nil {
		return err
	}
	actorID := p.UserID
	s.recordAudit(ctx, domain.AuditEvent{
		OrganizationID: &orgID,
		ActorUserID:    &actorID,
		ActorType:      actorTypeFromPrincipal(p),
		Action:         pkgAudit.ActionAPITokenRevoked.String(),
		ResourceType:   pkgAudit.TargetTypeAPIToken,
		ResourceID:     tokenID.String(),
	})
	return nil
}

// ValidateAPIToken validates a raw `kr0n_pat_...` token, verifies its hash in constant time,
// checks revocation, expiry, creator user status and creator's CURRENT org membership, and returns
// the token with permissions narrowed to what the creator's current role still grants.
func (s *OrgService) ValidateAPIToken(ctx context.Context, rawToken string) (*domain.APIToken, error) {
	rawToken = strings.TrimSpace(rawToken)
	if !strings.HasPrefix(rawToken, domain.APITokenPrefix) || len(rawToken) <= len(domain.APITokenPrefix) {
		return nil, domain.ErrInvalidAPIToken
	}
	tokenHash := domain.HashAPIToken(rawToken)
	tok, userStatus, err := s.repo.GetAPITokenByHash(ctx, tokenHash)
	if err != nil {
		if errors.Is(err, domain.ErrTokenNotFound) {
			return nil, domain.ErrInvalidAPIToken
		}
		return nil, err
	}
	if !domain.VerifyAPITokenHash(rawToken, tok.TokenHash) {
		return nil, domain.ErrInvalidAPIToken
	}
	now := time.Now().UTC()
	if tok.RevokedAt != nil || (tok.ExpiresAt != nil && !tok.ExpiresAt.After(now)) {
		return nil, domain.ErrInvalidAPIToken
	}
	if userStatus != domain.StatusActive {
		return nil, domain.ErrUserNotActive
	}

	_, rolePerms, err := s.repo.RolePermissions(ctx, tok.CreatedByUserID, tok.OrganizationID)
	if err != nil {
		if errors.Is(err, domain.ErrMemberNotFound) {
			return nil, domain.ErrInvalidAPIToken
		}
		return nil, err
	}
	effective := make([]string, 0, len(tok.Permissions))
	for _, perm := range tok.Permissions {
		if hasPermission(rolePerms, perm) {
			effective = append(effective, perm)
		}
	}
	tok.Permissions = effective

	if tok.LastUsedAt == nil || now.Sub(*tok.LastUsedAt) >= domain.LastUsedWriteInterval {
		_ = s.repo.TouchAPITokenLastUsed(ctx, tok.ID, now)
	}

	return tok, nil
}

func (s *OrgService) recordAudit(ctx context.Context, ev domain.AuditEvent) {
	if s.audit == nil {
		return
	}
	_ = s.audit.Record(ctx, ev)
}

func actorTypeFromPrincipal(p domain.Principal) string {
	if p.Kind == domain.ActorTypeAPIToken {
		return domain.ActorTypeAPIToken
	}
	return domain.ActorTypeUser
}
