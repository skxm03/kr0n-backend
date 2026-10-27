package service

import (
	"context"
	"errors"
	"log"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/skxm03/kr0n-backend/control-plane/internal/auth/repository"
)

var slugRegex = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*$`)

// InviteEmailSender dispatches organization invitation emails.
type InviteEmailSender interface {
	SendOrgInviteEmail(ctx context.Context, recipient, orgName, roleID, rawToken string) error
}

// OrgOption configures OrgService.
type OrgOption func(*OrgService)

// WithInviteEmailSender configures an optional email sender for organization invitations.
func WithInviteEmailSender(sender InviteEmailSender) OrgOption {
	return func(s *OrgService) {
		s.emailSender = sender
	}
}

// OrgService orchestrates organizations, memberships, invites, RBAC checks, and API tokens.
type OrgService struct {
	repo        repository.OrgRepository
	emailSender InviteEmailSender
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
func (s *OrgService) Can(ctx context.Context, p repository.Principal, orgID uuid.UUID, permission string) (bool, error) {
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
		if errors.Is(err, repository.ErrMemberNotFound) {
			return false, nil
		}
		return false, err
	}
	return hasPermission(perms, permission), nil
}

func hasPermission(perms []string, permission string) bool {
	for _, perm := range perms {
		if perm == permission {
			return true
		}
	}
	return false
}

func (s *OrgService) require(ctx context.Context, p repository.Principal, orgID uuid.UUID, permission string) error {
	allowed, err := s.Can(ctx, p, orgID, permission)
	if err != nil {
		return err
	}
	if !allowed {
		return repository.ErrForbidden
	}
	return nil
}

func validateRoleID(roleID string) bool {
	return roleID == "owner" || roleID == "admin" || roleID == "member"
}

// CreateOrg validates name and slug, then creates the organization with creatorUserID as owner.
func (s *OrgService) CreateOrg(ctx context.Context, creatorUserID uuid.UUID, name, slug string) (*repository.Organization, error) {
	name = strings.TrimSpace(name)
	slug = strings.ToLower(strings.TrimSpace(slug))
	if len(name) < 1 || len(name) > 100 || len(slug) < 2 || len(slug) > 63 || !slugRegex.MatchString(slug) {
		return nil, repository.ErrInvalidOrg
	}
	now := time.Now().UTC()
	o := &repository.Organization{
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
	return o, nil
}

// ListUserOrgs returns all organizations the user belongs to.
func (s *OrgService) ListUserOrgs(ctx context.Context, userID uuid.UUID) ([]repository.Organization, error) {
	return s.repo.ListUserOrgs(ctx, userID)
}

// GetOrg returns an organization if the principal has org:read.
func (s *OrgService) GetOrg(ctx context.Context, p repository.Principal, orgID uuid.UUID) (*repository.Organization, error) {
	if err := s.require(ctx, p, orgID, "org:read"); err != nil {
		return nil, err
	}
	return s.repo.GetOrg(ctx, orgID)
}

// UpdateOrg updates an organization's display name if the principal has org:update.
func (s *OrgService) UpdateOrg(ctx context.Context, p repository.Principal, orgID uuid.UUID, name string) (*repository.Organization, error) {
	if err := s.require(ctx, p, orgID, "org:update"); err != nil {
		return nil, err
	}
	name = strings.TrimSpace(name)
	if len(name) < 1 || len(name) > 100 {
		return nil, repository.ErrInvalidOrg
	}
	return s.repo.UpdateOrg(ctx, orgID, name, time.Now().UTC())
}

// DeleteOrg deletes an organization if the principal has org:delete.
func (s *OrgService) DeleteOrg(ctx context.Context, p repository.Principal, orgID uuid.UUID) error {
	if err := s.require(ctx, p, orgID, "org:delete"); err != nil {
		return err
	}
	return s.repo.DeleteOrg(ctx, orgID)
}

// ListRoles returns all seeded RBAC roles and their permissions.
func (s *OrgService) ListRoles(ctx context.Context) ([]repository.Role, error) {
	return s.repo.ListRoles(ctx)
}

// ListMembers lists organization members if the principal has member:read.
func (s *OrgService) ListMembers(ctx context.Context, p repository.Principal, orgID uuid.UUID) ([]repository.Member, error) {
	if err := s.require(ctx, p, orgID, "member:read"); err != nil {
		return nil, err
	}
	return s.repo.ListMembers(ctx, orgID)
}

// AddMember adds an existing user by email to the organization if the principal has member:create.
func (s *OrgService) AddMember(ctx context.Context, p repository.Principal, orgID uuid.UUID, rawEmail, roleID string) (*repository.Member, error) {
	if err := s.require(ctx, p, orgID, "member:create"); err != nil {
		return nil, err
	}
	roleID = strings.ToLower(strings.TrimSpace(roleID))
	if !validateRoleID(roleID) {
		return nil, repository.ErrInvalidRole
	}
	email, err := repository.CanonicalizeEmail(rawEmail)
	if err != nil {
		return nil, err
	}
	return s.repo.AddMemberByEmail(ctx, orgID, email, roleID, time.Now().UTC())
}

// UpdateMemberRole updates a member's role if the principal has member:update, enforcing the last-owner guard.
func (s *OrgService) UpdateMemberRole(ctx context.Context, p repository.Principal, orgID, targetUserID uuid.UUID, roleID string) error {
	if err := s.require(ctx, p, orgID, "member:update"); err != nil {
		return err
	}
	roleID = strings.ToLower(strings.TrimSpace(roleID))
	if !validateRoleID(roleID) {
		return repository.ErrInvalidRole
	}
	return s.repo.UpdateMemberRole(ctx, orgID, targetUserID, roleID, time.Now().UTC())
}

// RemoveMember removes a member from an organization if the principal has member:delete, enforcing the last-owner guard.
func (s *OrgService) RemoveMember(ctx context.Context, p repository.Principal, orgID, targetUserID uuid.UUID) error {
	if err := s.require(ctx, p, orgID, "member:delete"); err != nil {
		return err
	}
	return s.repo.RemoveMember(ctx, orgID, targetUserID)
}

// CreateInvite creates an organization invite token if the principal has member:create.
func (s *OrgService) CreateInvite(ctx context.Context, p repository.Principal, orgID uuid.UUID, rawEmail, roleID string) (*repository.Invite, string, error) {
	if err := s.require(ctx, p, orgID, "member:create"); err != nil {
		return nil, "", err
	}
	roleID = strings.ToLower(strings.TrimSpace(roleID))
	if !validateRoleID(roleID) {
		return nil, "", repository.ErrInvalidRole
	}
	email, err := repository.CanonicalizeEmail(rawEmail)
	if err != nil {
		return nil, "", err
	}
	rawToken, err := repository.GenerateToken()
	if err != nil {
		return nil, "", err
	}
	now := time.Now().UTC()
	inv := &repository.Invite{
		ID:              uuid.New(),
		OrganizationID:  orgID,
		Email:           email,
		RoleID:          roleID,
		InvitedByUserID: p.UserID,
		TokenHash:       repository.HashToken(rawToken),
		ExpiresAt:       now.Add(7 * 24 * time.Hour),
		CreatedAt:       now,
	}
	if err := s.repo.CreateInvite(ctx, inv); err != nil {
		return nil, "", err
	}

	if s.emailSender != nil {
		orgName := "kr0n organization"
		if o, err := s.repo.GetOrg(ctx, orgID); err == nil && o != nil {
			orgName = o.Name
		}
		emailCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		if err := s.emailSender.SendOrgInviteEmail(emailCtx, inv.Email, orgName, inv.RoleID, rawToken); err != nil {
			log.Printf("failed to dispatch invite email to %s: %v", inv.Email, err)
		}
	}

	return inv, rawToken, nil
}

// AcceptInvite consumes an invite token and adds userID to the organization.
func (s *OrgService) AcceptInvite(ctx context.Context, userID uuid.UUID, rawToken string) (*repository.Organization, error) {
	rawToken = strings.TrimSpace(rawToken)
	if userID == uuid.Nil || rawToken == "" {
		return nil, repository.ErrInvalidInviteToken
	}
	return s.repo.AcceptInvite(ctx, userID, repository.HashToken(rawToken), time.Now().UTC())
}

// RevokeInvite revokes a pending organization invite if the principal has member:delete.
func (s *OrgService) RevokeInvite(ctx context.Context, p repository.Principal, orgID, inviteID uuid.UUID) error {
	if err := s.require(ctx, p, orgID, "member:delete"); err != nil {
		return err
	}
	return s.repo.RevokeInvite(ctx, orgID, inviteID, time.Now().UTC())
}

// CreateAPIToken issues an org-scoped API token (`kr0n_pat_...`) whose permissions must be a subset
// of the caller's effective permissions in the organization.
func (s *OrgService) CreateAPIToken(ctx context.Context, p repository.Principal, orgID uuid.UUID, name string, requestedPerms []string, expiresInSeconds int64) (*repository.APIToken, string, error) {
	if p.Kind == "api_token" {
		return nil, "", repository.ErrForbidden
	}
	if err := s.require(ctx, p, orgID, "apitoken:create"); err != nil {
		return nil, "", err
	}
	name = strings.TrimSpace(name)
	if len(name) < 1 || len(name) > 100 || len(requestedPerms) == 0 {
		return nil, "", repository.ErrInvalidAPIToken
	}

	for _, perm := range requestedPerms {
		ok, err := s.Can(ctx, p, orgID, perm)
		if err != nil {
			return nil, "", err
		}
		if !ok {
			return nil, "", repository.ErrForbidden
		}
	}

	rawToken, prefix, tokenHash, err := repository.GenerateAPIToken()
	if err != nil {
		return nil, "", err
	}
	now := time.Now().UTC()
	var expiresAt *time.Time
	if expiresInSeconds > 0 {
		exp := now.Add(time.Duration(expiresInSeconds) * time.Second)
		expiresAt = &exp
	}

	tok := &repository.APIToken{
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
	return tok, rawToken, nil
}

// ListAPITokens lists non-revoked API tokens for an organization if the principal has apitoken:read.
func (s *OrgService) ListAPITokens(ctx context.Context, p repository.Principal, orgID uuid.UUID) ([]repository.APIToken, error) {
	if err := s.require(ctx, p, orgID, "apitoken:read"); err != nil {
		return nil, err
	}
	return s.repo.ListAPITokens(ctx, orgID)
}

// RevokeAPIToken revokes an API token if the principal has apitoken:delete.
func (s *OrgService) RevokeAPIToken(ctx context.Context, p repository.Principal, orgID, tokenID uuid.UUID) error {
	if err := s.require(ctx, p, orgID, "apitoken:delete"); err != nil {
		return err
	}
	return s.repo.RevokeAPIToken(ctx, orgID, tokenID, time.Now().UTC())
}

// ValidateAPIToken validates a raw `kr0n_pat_...` token, verifies its hash in constant time,
// checks revocation, expiry, creator user status and creator's CURRENT org membership, and returns
// the token with permissions narrowed to what the creator's current role still grants.
func (s *OrgService) ValidateAPIToken(ctx context.Context, rawToken string) (*repository.APIToken, error) {
	rawToken = strings.TrimSpace(rawToken)
	if !strings.HasPrefix(rawToken, repository.APITokenPrefix) || len(rawToken) <= len(repository.APITokenPrefix) {
		return nil, repository.ErrInvalidAPIToken
	}
	tokenHash := repository.HashAPIToken(rawToken)
	tok, userStatus, err := s.repo.GetAPITokenByHash(ctx, tokenHash)
	if err != nil {
		if errors.Is(err, repository.ErrTokenNotFound) {
			return nil, repository.ErrInvalidAPIToken
		}
		return nil, err
	}
	if !repository.VerifyAPITokenHash(rawToken, tok.TokenHash) {
		return nil, repository.ErrInvalidAPIToken
	}
	now := time.Now().UTC()
	if tok.RevokedAt != nil || (tok.ExpiresAt != nil && !tok.ExpiresAt.After(now)) {
		return nil, repository.ErrInvalidAPIToken
	}
	if userStatus != repository.StatusActive {
		return nil, repository.ErrUserNotActive
	}

	_, rolePerms, err := s.repo.RolePermissions(ctx, tok.CreatedByUserID, tok.OrganizationID)
	if err != nil {
		if errors.Is(err, repository.ErrMemberNotFound) {
			return nil, repository.ErrInvalidAPIToken
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

	if tok.LastUsedAt == nil || now.Sub(*tok.LastUsedAt) >= repository.LastUsedWriteInterval {
		_ = s.repo.TouchAPITokenLastUsed(ctx, tok.ID, now)
	}

	return tok, nil
}
