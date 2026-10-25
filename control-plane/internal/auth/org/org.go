package org

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/skxm03/kr0n-backend/control-plane/internal/auth/user"
	"github.com/skxm03/kr0n-backend/control-plane/internal/auth/verification"
)

const (
	// APITokenPrefix is the mandatory prefix for personal/org API tokens.
	APITokenPrefix = "kr0n_pat_"

	// lastUsedWriteInterval bounds how often api_tokens.last_used_at is written per token.
	lastUsedWriteInterval = 5 * time.Minute
)

var (
	ErrOrgNotFound         = errors.New("organization not found")
	ErrSlugAlreadyExists   = errors.New("organization slug already exists")
	ErrInvalidOrg          = errors.New("invalid organization name or slug")
	ErrInvalidRole         = errors.New("invalid role")
	ErrForbidden           = errors.New("insufficient permissions")
	ErrLastOwner           = errors.New("cannot remove or demote the last organization owner")
	ErrMemberNotFound      = errors.New("organization member not found")
	ErrMemberAlreadyExists = errors.New("user is already a member of this organization")
	ErrInviteNotFound      = errors.New("organization invite not found")
	ErrInvalidInviteToken  = errors.New("invalid or expired organization invite token")
	ErrTokenNotFound       = errors.New("api token not found")
	ErrInvalidAPIToken     = errors.New("invalid api token")
)

var slugRegex = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*$`)

// Principal represents an authenticated caller evaluated by the authorization service.
type Principal struct {
	UserID           uuid.UUID
	Kind             string // "session" or "api_token"
	TokenOrgID       *uuid.UUID
	TokenPermissions []string
}

// Organization represents a tenant organization.
type Organization struct {
	ID        uuid.UUID
	Name      string
	Slug      string
	RoleID    string
	CreatedAt time.Time
	UpdatedAt time.Time
}

// Member represents a user's membership in an organization.
type Member struct {
	UserID      uuid.UUID
	Email       string
	DisplayName string
	RoleID      string
	CreatedAt   time.Time
}

// Invite represents a pending or consumed organization invitation.
type Invite struct {
	ID              uuid.UUID
	OrganizationID  uuid.UUID
	Email           string
	RoleID          string
	InvitedByUserID uuid.UUID
	TokenHash       string
	ExpiresAt       time.Time
	AcceptedAt      *time.Time
	RevokedAt       *time.Time
	CreatedAt       time.Time
}

// Role represents a named RBAC role and its granted permissions.
type Role struct {
	ID          string
	Name        string
	Description string
	Permissions []string
}

// APIToken represents an organization-scoped API token (`kr0n_pat_...`).
type APIToken struct {
	ID              uuid.UUID
	OrganizationID  uuid.UUID
	CreatedByUserID uuid.UUID
	Name            string
	TokenPrefix     string
	TokenHash       string
	Permissions     []string
	ExpiresAt       *time.Time
	LastUsedAt      *time.Time
	RevokedAt       *time.Time
	CreatedAt       time.Time
}

// GenerateAPIToken generates a `kr0n_pat_<64 hex>` secret, its display prefix, and its SHA-256 hash.
func GenerateAPIToken() (rawToken, prefix, tokenHash string, err error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", "", "", fmt.Errorf("generate random token: %w", err)
	}
	rawToken = APITokenPrefix + hex.EncodeToString(b)
	prefix = rawToken[:17] // "kr0n_pat_" + 8 hex chars
	tokenHash = HashAPIToken(rawToken)
	return rawToken, prefix, tokenHash, nil
}

// HashAPIToken computes the SHA-256 hex digest of a raw API token.
func HashAPIToken(rawToken string) string {
	sum := sha256.Sum256([]byte(rawToken))
	return hex.EncodeToString(sum[:])
}

// VerifyAPITokenHash compares a raw API token's SHA-256 digest against storedHash in constant time.
func VerifyAPITokenHash(rawToken, storedHash string) bool {
	h := HashAPIToken(rawToken)
	return subtle.ConstantTimeCompare([]byte(h), []byte(storedHash)) == 1
}

// Repository defines persistence operations for organizations, RBAC, invites, and API tokens.
type Repository interface {
	RolePermissions(ctx context.Context, userID, orgID uuid.UUID) (roleID string, permissions []string, err error)
	ListRoles(ctx context.Context) ([]Role, error)

	CreateOrg(ctx context.Context, org *Organization, ownerUserID uuid.UUID) error
	ListUserOrgs(ctx context.Context, userID uuid.UUID) ([]Organization, error)
	GetOrg(ctx context.Context, orgID uuid.UUID) (*Organization, error)
	UpdateOrg(ctx context.Context, orgID uuid.UUID, name string, now time.Time) (*Organization, error)
	DeleteOrg(ctx context.Context, orgID uuid.UUID) error

	ListMembers(ctx context.Context, orgID uuid.UUID) ([]Member, error)
	AddMemberByEmail(ctx context.Context, orgID uuid.UUID, email, roleID string, now time.Time) (*Member, error)
	UpdateMemberRole(ctx context.Context, orgID, targetUserID uuid.UUID, roleID string, now time.Time) error
	RemoveMember(ctx context.Context, orgID, targetUserID uuid.UUID) error

	CreateInvite(ctx context.Context, inv *Invite) error
	AcceptInvite(ctx context.Context, userID uuid.UUID, tokenHash string, now time.Time) (*Organization, error)
	RevokeInvite(ctx context.Context, orgID, inviteID uuid.UUID, now time.Time) error

	CreateAPIToken(ctx context.Context, tok *APIToken) error
	ListAPITokens(ctx context.Context, orgID uuid.UUID) ([]APIToken, error)
	RevokeAPIToken(ctx context.Context, orgID, tokenID uuid.UUID, now time.Time) error
	GetAPITokenByHash(ctx context.Context, tokenHash string) (*APIToken, user.Status, error)
	TouchAPITokenLastUsed(ctx context.Context, tokenID uuid.UUID, usedAt time.Time) error
}

// InviteEmailSender dispatches organization invitation emails.
type InviteEmailSender interface {
	SendOrgInviteEmail(ctx context.Context, recipient, orgName, roleID, rawToken string) error
}

// Option configures Service.
type Option func(*Service)

// WithInviteEmailSender configures an optional email sender for organization invitations.
func WithInviteEmailSender(sender InviteEmailSender) Option {
	return func(s *Service) {
		s.emailSender = sender
	}
}

// Service orchestrates organizations, memberships, invites, RBAC checks, and API tokens.
type Service struct {
	repo        Repository
	emailSender InviteEmailSender
}

// NewService constructs an org Service.
func NewService(repo Repository, opts ...Option) *Service {
	s := &Service{repo: repo}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// Can evaluates whether principal holds permission in orgID.
//
// Authorization policy for API tokens: the effective permissions are the INTERSECTION of
// (a) the permissions explicitly granted to the token at creation time, and
// (b) the permissions the token's creator holds RIGHT NOW through their current membership role.
// The role lookup runs on every check (no cached snapshot), so a removed or demoted creator loses
// access on the very next authorization check. Re-promotion never grants more than (a).
func (s *Service) Can(ctx context.Context, p Principal, orgID uuid.UUID, permission string) (bool, error) {
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
		if errors.Is(err, ErrMemberNotFound) {
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

func (s *Service) require(ctx context.Context, p Principal, orgID uuid.UUID, permission string) error {
	allowed, err := s.Can(ctx, p, orgID, permission)
	if err != nil {
		return err
	}
	if !allowed {
		return ErrForbidden
	}
	return nil
}

func validateRoleID(roleID string) bool {
	return roleID == "owner" || roleID == "admin" || roleID == "member"
}

// CreateOrg validates name and slug, then creates the organization with creatorUserID as owner.
func (s *Service) CreateOrg(ctx context.Context, creatorUserID uuid.UUID, name, slug string) (*Organization, error) {
	name = strings.TrimSpace(name)
	slug = strings.ToLower(strings.TrimSpace(slug))
	if len(name) < 1 || len(name) > 100 || len(slug) < 2 || len(slug) > 63 || !slugRegex.MatchString(slug) {
		return nil, ErrInvalidOrg
	}
	now := time.Now().UTC()
	o := &Organization{
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
func (s *Service) ListUserOrgs(ctx context.Context, userID uuid.UUID) ([]Organization, error) {
	return s.repo.ListUserOrgs(ctx, userID)
}

// GetOrg returns an organization if the principal has org:read.
func (s *Service) GetOrg(ctx context.Context, p Principal, orgID uuid.UUID) (*Organization, error) {
	if err := s.require(ctx, p, orgID, "org:read"); err != nil {
		return nil, err
	}
	return s.repo.GetOrg(ctx, orgID)
}

// UpdateOrg updates an organization's display name if the principal has org:update.
func (s *Service) UpdateOrg(ctx context.Context, p Principal, orgID uuid.UUID, name string) (*Organization, error) {
	if err := s.require(ctx, p, orgID, "org:update"); err != nil {
		return nil, err
	}
	name = strings.TrimSpace(name)
	if len(name) < 1 || len(name) > 100 {
		return nil, ErrInvalidOrg
	}
	return s.repo.UpdateOrg(ctx, orgID, name, time.Now().UTC())
}

// DeleteOrg deletes an organization if the principal has org:delete.
func (s *Service) DeleteOrg(ctx context.Context, p Principal, orgID uuid.UUID) error {
	if err := s.require(ctx, p, orgID, "org:delete"); err != nil {
		return err
	}
	return s.repo.DeleteOrg(ctx, orgID)
}

// ListRoles returns all seeded RBAC roles and their permissions.
func (s *Service) ListRoles(ctx context.Context) ([]Role, error) {
	return s.repo.ListRoles(ctx)
}

// ListMembers lists organization members if the principal has member:read.
func (s *Service) ListMembers(ctx context.Context, p Principal, orgID uuid.UUID) ([]Member, error) {
	if err := s.require(ctx, p, orgID, "member:read"); err != nil {
		return nil, err
	}
	return s.repo.ListMembers(ctx, orgID)
}

// AddMember adds an existing user by email to the organization if the principal has member:create.
func (s *Service) AddMember(ctx context.Context, p Principal, orgID uuid.UUID, rawEmail, roleID string) (*Member, error) {
	if err := s.require(ctx, p, orgID, "member:create"); err != nil {
		return nil, err
	}
	roleID = strings.ToLower(strings.TrimSpace(roleID))
	if !validateRoleID(roleID) {
		return nil, ErrInvalidRole
	}
	email, err := user.CanonicalizeEmail(rawEmail)
	if err != nil {
		return nil, err
	}
	return s.repo.AddMemberByEmail(ctx, orgID, email, roleID, time.Now().UTC())
}

// UpdateMemberRole updates a member's role if the principal has member:update, enforcing the last-owner guard.
func (s *Service) UpdateMemberRole(ctx context.Context, p Principal, orgID, targetUserID uuid.UUID, roleID string) error {
	if err := s.require(ctx, p, orgID, "member:update"); err != nil {
		return err
	}
	roleID = strings.ToLower(strings.TrimSpace(roleID))
	if !validateRoleID(roleID) {
		return ErrInvalidRole
	}
	return s.repo.UpdateMemberRole(ctx, orgID, targetUserID, roleID, time.Now().UTC())
}

// RemoveMember removes a member from an organization if the principal has member:delete, enforcing the last-owner guard.
func (s *Service) RemoveMember(ctx context.Context, p Principal, orgID, targetUserID uuid.UUID) error {
	if err := s.require(ctx, p, orgID, "member:delete"); err != nil {
		return err
	}
	return s.repo.RemoveMember(ctx, orgID, targetUserID)
}

// CreateInvite creates an organization invite token if the principal has member:create.
func (s *Service) CreateInvite(ctx context.Context, p Principal, orgID uuid.UUID, rawEmail, roleID string) (*Invite, string, error) {
	if err := s.require(ctx, p, orgID, "member:create"); err != nil {
		return nil, "", err
	}
	roleID = strings.ToLower(strings.TrimSpace(roleID))
	if !validateRoleID(roleID) {
		return nil, "", ErrInvalidRole
	}
	email, err := user.CanonicalizeEmail(rawEmail)
	if err != nil {
		return nil, "", err
	}
	rawToken, err := verification.GenerateToken()
	if err != nil {
		return nil, "", err
	}
	now := time.Now().UTC()
	inv := &Invite{
		ID:              uuid.New(),
		OrganizationID:  orgID,
		Email:           email,
		RoleID:          roleID,
		InvitedByUserID: p.UserID,
		TokenHash:       verification.HashToken(rawToken),
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
func (s *Service) AcceptInvite(ctx context.Context, userID uuid.UUID, rawToken string) (*Organization, error) {
	rawToken = strings.TrimSpace(rawToken)
	if userID == uuid.Nil || rawToken == "" {
		return nil, ErrInvalidInviteToken
	}
	return s.repo.AcceptInvite(ctx, userID, verification.HashToken(rawToken), time.Now().UTC())
}

// RevokeInvite revokes a pending organization invite if the principal has member:delete.
func (s *Service) RevokeInvite(ctx context.Context, p Principal, orgID, inviteID uuid.UUID) error {
	if err := s.require(ctx, p, orgID, "member:delete"); err != nil {
		return err
	}
	return s.repo.RevokeInvite(ctx, orgID, inviteID, time.Now().UTC())
}

// CreateAPIToken issues an org-scoped API token (`kr0n_pat_...`) whose permissions must be a subset
// of the caller's effective permissions in the organization.
func (s *Service) CreateAPIToken(ctx context.Context, p Principal, orgID uuid.UUID, name string, requestedPerms []string, expiresInSeconds int64) (*APIToken, string, error) {
	// API tokens can never mint further tokens: a derived token could outlive the parent's expiry
	// or revocation, which would defeat both. Only interactive user sessions may delegate.
	if p.Kind == "api_token" {
		return nil, "", ErrForbidden
	}
	if err := s.require(ctx, p, orgID, "apitoken:create"); err != nil {
		return nil, "", err
	}
	name = strings.TrimSpace(name)
	if len(name) < 1 || len(name) > 100 || len(requestedPerms) == 0 {
		return nil, "", ErrInvalidAPIToken
	}

	// Verify requested permissions are a subset of the caller's effective permissions
	for _, perm := range requestedPerms {
		ok, err := s.Can(ctx, p, orgID, perm)
		if err != nil {
			return nil, "", err
		}
		if !ok {
			return nil, "", ErrForbidden
		}
	}

	rawToken, prefix, tokenHash, err := GenerateAPIToken()
	if err != nil {
		return nil, "", err
	}
	now := time.Now().UTC()
	var expiresAt *time.Time
	if expiresInSeconds > 0 {
		exp := now.Add(time.Duration(expiresInSeconds) * time.Second)
		expiresAt = &exp
	}

	tok := &APIToken{
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
func (s *Service) ListAPITokens(ctx context.Context, p Principal, orgID uuid.UUID) ([]APIToken, error) {
	if err := s.require(ctx, p, orgID, "apitoken:read"); err != nil {
		return nil, err
	}
	return s.repo.ListAPITokens(ctx, orgID)
}

// RevokeAPIToken revokes an API token if the principal has apitoken:delete.
func (s *Service) RevokeAPIToken(ctx context.Context, p Principal, orgID, tokenID uuid.UUID) error {
	if err := s.require(ctx, p, orgID, "apitoken:delete"); err != nil {
		return err
	}
	return s.repo.RevokeAPIToken(ctx, orgID, tokenID, time.Now().UTC())
}

// ValidateAPIToken validates a raw `kr0n_pat_...` token, verifies its hash in constant time,
// checks revocation, expiry, creator user status and creator's CURRENT org membership, and returns
// the token with permissions narrowed to what the creator's current role still grants.
// last_used_at is updated at most once per lastUsedWriteInterval.
func (s *Service) ValidateAPIToken(ctx context.Context, rawToken string) (*APIToken, error) {
	rawToken = strings.TrimSpace(rawToken)
	if !strings.HasPrefix(rawToken, APITokenPrefix) || len(rawToken) <= len(APITokenPrefix) {
		return nil, ErrInvalidAPIToken
	}
	tokenHash := HashAPIToken(rawToken)
	tok, userStatus, err := s.repo.GetAPITokenByHash(ctx, tokenHash)
	if err != nil {
		if errors.Is(err, ErrTokenNotFound) {
			return nil, ErrInvalidAPIToken
		}
		return nil, err
	}
	if !VerifyAPITokenHash(rawToken, tok.TokenHash) {
		return nil, ErrInvalidAPIToken
	}
	now := time.Now().UTC()
	if tok.RevokedAt != nil || (tok.ExpiresAt != nil && !tok.ExpiresAt.After(now)) {
		return nil, ErrInvalidAPIToken
	}
	if userStatus != user.StatusActive {
		return nil, user.ErrUserNotActive
	}

	// The creator must still be a member; effective permissions are narrowed to the creator's
	// current role (see Can). A removed creator makes the token invalid immediately.
	_, rolePerms, err := s.repo.RolePermissions(ctx, tok.CreatedByUserID, tok.OrganizationID)
	if err != nil {
		if errors.Is(err, ErrMemberNotFound) {
			return nil, ErrInvalidAPIToken
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

	// Throttled, synchronous bookkeeping: at most one write per token per interval, no goroutine.
	if tok.LastUsedAt == nil || now.Sub(*tok.LastUsedAt) >= lastUsedWriteInterval {
		_ = s.repo.TouchAPITokenLastUsed(ctx, tok.ID, now)
	}

	return tok, nil
}
