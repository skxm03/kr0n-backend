package service

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/skxm03/kr0n-backend/control-plane/internal/auth/oauth"
	"github.com/skxm03/kr0n-backend/control-plane/internal/auth/repository"
	emailpkg "github.com/skxm03/kr0n-backend/control-plane/internal/email"
)

var slugRegex = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*$`)

// GitHubAppClient defines the GitHub App installation and token operations required by OrgService.
type GitHubAppClient interface {
	Configured() bool
	StartInstallation(orgID, userID uuid.UUID) (installURL, state string, err error)
	VerifyState(state string, expectedOrgID, expectedUserID uuid.UUID) error
	GetInstallation(ctx context.Context, installationID int64) (*oauth.GitHubAppInstallation, error)
	GetInstallationToken(ctx context.Context, installationID int64) (string, time.Time, error)
}

// OrgOption configures OrgService.
type OrgOption func(*OrgService)

// WithOrgOutboxNotifier wires an outbox notifier to OrgService.
func WithOrgOutboxNotifier(notifier OutboxNotifier) OrgOption {
	return func(s *OrgService) {
		s.notifier = notifier
	}
}

// WithGitHubApp configures an optional GitHub App client for organization GitHub installations and repository browsing.
func WithGitHubApp(gh GitHubAppClient) OrgOption {
	return func(s *OrgService) {
		s.githubApp = gh
	}
}

// OrgService orchestrates organizations, memberships, invites, RBAC checks, and API tokens.
type OrgService struct {
	repo      repository.OrgRepository
	notifier  OutboxNotifier
	githubApp GitHubAppClient
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

	orgName := "kr0n organization"
	if o, err := s.repo.GetOrg(ctx, orgID); err == nil && o != nil {
		orgName = o.Name
	}

	outboxEv := &repository.OutboxEvent{
		ID:            newUUIDv7(),
		EventType:     repository.EventTypeOrgInvite,
		AggregateType: "organization",
		AggregateID:   orgID,
		Payload: map[string]any{
			"id":        newUUIDv7().String(),
			"type":      string(emailpkg.TemplateOrgInvite),
			"recipient": inv.Email,
			"data": map[string]string{
				"org_name": orgName,
				"role_id":  inv.RoleID,
				"token":    rawToken,
			},
			"created_at": now.Format(time.RFC3339),
		},
		Headers:     map[string]any{},
		Status:      repository.OutboxStatusPending,
		CreatedAt:   now,
		ScheduledAt: now,
	}

	if err := s.repo.CreateInvite(ctx, inv, outboxEv); err != nil {
		return nil, "", err
	}

	if s.notifier != nil {
		s.notifier.Notify()
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

// StartGitHubInstallation generates a signed installation state token and GitHub App installation URL if the principal holds org:update.
func (s *OrgService) StartGitHubInstallation(ctx context.Context, p repository.Principal, orgID uuid.UUID) (installURL, state string, err error) {
	if err := s.require(ctx, p, orgID, "org:update"); err != nil {
		return "", "", err
	}
	if s.githubApp == nil || !s.githubApp.Configured() {
		return "", "", oauth.ErrGitHubAppNotConfigured
	}
	return s.githubApp.StartInstallation(orgID, p.UserID)
}

// CompleteGitHubInstallation verifies the state token, fetches installation metadata from GitHub, and links it to the organization.
func (s *OrgService) CompleteGitHubInstallation(ctx context.Context, p repository.Principal, orgID uuid.UUID, installationID int64, state string) (*repository.GitHubInstallation, error) {
	if err := s.require(ctx, p, orgID, "org:update"); err != nil {
		return nil, err
	}
	if s.githubApp == nil || !s.githubApp.Configured() {
		return nil, oauth.ErrGitHubAppNotConfigured
	}
	if installationID <= 0 {
		return nil, oauth.ErrInvalidInstallationState
	}
	if err := s.githubApp.VerifyState(state, orgID, p.UserID); err != nil {
		return nil, err
	}
	meta, err := s.githubApp.GetInstallation(ctx, installationID)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	inst := &repository.GitHubInstallation{
		ID:                  uuid.New(),
		OrganizationID:      orgID,
		InstallationID:      meta.InstallationID,
		AccountLogin:        meta.AccountLogin,
		AccountType:         meta.AccountType,
		RepositorySelection: meta.RepositorySelection,
		Status:              meta.Status,
		CreatedByUserID:     p.UserID,
		CreatedAt:           now,
		UpdatedAt:           now,
	}
	return s.repo.UpsertGitHubInstallation(ctx, inst)
}

// ListGitHubInstallations lists GitHub App installations linked to the organization if the principal holds service:read or org:read.
func (s *OrgService) ListGitHubInstallations(ctx context.Context, p repository.Principal, orgID uuid.UUID) ([]repository.GitHubInstallation, error) {
	if err := s.require(ctx, p, orgID, "service:read"); err != nil {
		if err2 := s.require(ctx, p, orgID, "org:read"); err2 != nil {
			return nil, err
		}
	}
	return s.repo.ListGitHubInstallations(ctx, orgID)
}

// DisconnectGitHubInstallation unlinks a GitHub App installation from the organization if the principal holds org:update.
func (s *OrgService) DisconnectGitHubInstallation(ctx context.Context, p repository.Principal, orgID uuid.UUID, installationID int64) error {
	if err := s.require(ctx, p, orgID, "org:update"); err != nil {
		return err
	}
	if err := s.repo.DeleteGitHubInstallation(ctx, orgID, installationID); err != nil {
		return err
	}
	s.InvalidateGitHubInstallationToken(installationID)
	return nil
}

// UpdateGitHubInstallationStatus updates the lifecycle status ('active', 'suspended', 'deleted') of an installation
// in response to a verified GitHub webhook event, evicts any cached installation token when non-active,
// and returns the installation record (if linked to an organization).
func (s *OrgService) UpdateGitHubInstallationStatus(ctx context.Context, installationID int64, status string) (*repository.GitHubInstallation, error) {
	if installationID <= 0 {
		return nil, repository.ErrInstallationNotFound
	}
	status = strings.ToLower(strings.TrimSpace(status))
	if status != "active" {
		s.InvalidateGitHubInstallationToken(installationID)
	}
	inst, err := s.repo.GetGitHubInstallationByInstallationID(ctx, installationID)
	if err != nil {
		return nil, err
	}
	if err := s.repo.UpdateGitHubInstallationStatus(ctx, installationID, status); err != nil {
		return nil, err
	}
	inst.Status = status
	return inst, nil
}

// GetGitHubInstallationByInstallationID looks up a linked installation by its GitHub installation_id.
func (s *OrgService) GetGitHubInstallationByInstallationID(ctx context.Context, installationID int64) (*repository.GitHubInstallation, error) {
	if installationID <= 0 {
		return nil, repository.ErrInstallationNotFound
	}
	return s.repo.GetGitHubInstallationByInstallationID(ctx, installationID)
}

// InvalidateGitHubInstallationToken evicts any cached installation token for installationID.
func (s *OrgService) InvalidateGitHubInstallationToken(installationID int64) {
	if inv, ok := s.githubApp.(interface{ InvalidateInstallationToken(int64) }); ok {
		inv.InvalidateInstallationToken(installationID)
	}
}

// GetInstallationToken authorizes caller with service:read, resolves the installation, and mints an ephemeral GitHub App token.
func (s *OrgService) GetInstallationToken(ctx context.Context, p repository.Principal, orgID uuid.UUID, installationID int64) (string, int64, time.Time, error) {
	instID, err := s.resolveOrgGitHubInstallation(ctx, p, orgID, installationID)
	if err != nil {
		return "", 0, time.Time{}, err
	}
	tok, exp, err := s.githubApp.GetInstallationToken(ctx, instID)
	if err != nil {
		return "", 0, time.Time{}, err
	}
	return tok, instID, exp, nil
}

func (s *OrgService) resolveOrgGitHubInstallation(ctx context.Context, p repository.Principal, orgID uuid.UUID, installationID int64) (int64, error) {
	if err := s.require(ctx, p, orgID, "service:read"); err != nil {
		return 0, err
	}
	if s.githubApp == nil || !s.githubApp.Configured() {
		return 0, oauth.ErrGitHubAppNotConfigured
	}
	installations, err := s.repo.ListGitHubInstallations(ctx, orgID)
	if err != nil {
		return 0, err
	}
	if installationID <= 0 {
		for _, inst := range installations {
			if inst.Status == "" || inst.Status == "active" {
				return inst.InstallationID, nil
			}
		}
		return 0, repository.ErrInstallationNotFound
	}
	for _, inst := range installations {
		if inst.InstallationID == installationID && (inst.Status == "" || inst.Status == "active") {
			return inst.InstallationID, nil
		}
	}
	return 0, repository.ErrInstallationNotFound
}
