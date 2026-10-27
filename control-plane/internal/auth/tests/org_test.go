package tests

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/skxm03/kr0n-backend/control-plane/internal/auth/repository"
	"github.com/skxm03/kr0n-backend/control-plane/internal/auth/service"
)

type memOrgRepo struct {
	mu          sync.Mutex
	orgs        map[uuid.UUID]*repository.Organization
	members     map[uuid.UUID]map[uuid.UUID]string // orgID -> userID -> roleID
	usersByMail map[string]uuid.UUID
	invites     map[string]*repository.Invite // tokenHash -> Invite
	tokens      map[string]*repository.APIToken
	rolePerms   map[string][]string
}

func newMemOrgRepo() *memOrgRepo {
	return &memOrgRepo{
		orgs:        make(map[uuid.UUID]*repository.Organization),
		members:     make(map[uuid.UUID]map[uuid.UUID]string),
		usersByMail: make(map[string]uuid.UUID),
		invites:     make(map[string]*repository.Invite),
		tokens:      make(map[string]*repository.APIToken),
		rolePerms: map[string][]string{
			"owner":  {"org:read", "org:update", "org:delete", "member:read", "member:create", "member:update", "member:delete", "apitoken:read", "apitoken:create", "apitoken:delete", "project:read", "project:create"},
			"admin":  {"org:read", "org:update", "member:read", "member:create", "member:update", "member:delete", "apitoken:read", "apitoken:create", "apitoken:delete", "project:read", "project:create"},
			"member": {"org:read", "member:read", "project:read"},
		},
	}
}

func (m *memOrgRepo) RolePermissions(ctx context.Context, userID, orgID uuid.UUID) (string, []string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	role, ok := m.members[orgID][userID]
	if !ok {
		return "", nil, repository.ErrMemberNotFound
	}
	return role, m.rolePerms[role], nil
}

func (m *memOrgRepo) ListRoles(ctx context.Context) ([]repository.Role, error) {
	return []repository.Role{
		{ID: "owner", Name: "Owner", Permissions: m.rolePerms["owner"]},
		{ID: "admin", Name: "Admin", Permissions: m.rolePerms["admin"]},
		{ID: "member", Name: "Member", Permissions: m.rolePerms["member"]},
	}, nil
}

func (m *memOrgRepo) CreateOrg(ctx context.Context, o *repository.Organization, ownerUserID uuid.UUID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, existing := range m.orgs {
		if existing.Slug == o.Slug {
			return repository.ErrSlugAlreadyExists
		}
	}
	cp := *o
	m.orgs[o.ID] = &cp
	if m.members[o.ID] == nil {
		m.members[o.ID] = make(map[uuid.UUID]string)
	}
	m.members[o.ID][ownerUserID] = "owner"
	return nil
}

func (m *memOrgRepo) ListUserOrgs(ctx context.Context, userID uuid.UUID) ([]repository.Organization, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []repository.Organization
	for oid, members := range m.members {
		if role, ok := members[userID]; ok {
			cp := *m.orgs[oid]
			cp.RoleID = role
			out = append(out, cp)
		}
	}
	return out, nil
}

func (m *memOrgRepo) GetOrg(ctx context.Context, orgID uuid.UUID) (*repository.Organization, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	o, ok := m.orgs[orgID]
	if !ok {
		return nil, repository.ErrOrgNotFound
	}
	cp := *o
	return &cp, nil
}

func (m *memOrgRepo) UpdateOrg(ctx context.Context, orgID uuid.UUID, name string, now time.Time) (*repository.Organization, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	o, ok := m.orgs[orgID]
	if !ok {
		return nil, repository.ErrOrgNotFound
	}
	o.Name = name
	o.UpdatedAt = now
	cp := *o
	return &cp, nil
}

func (m *memOrgRepo) DeleteOrg(ctx context.Context, orgID uuid.UUID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.orgs[orgID]; !ok {
		return repository.ErrOrgNotFound
	}
	delete(m.orgs, orgID)
	delete(m.members, orgID)
	return nil
}

func (m *memOrgRepo) ListMembers(ctx context.Context, orgID uuid.UUID) ([]repository.Member, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []repository.Member
	for uid, role := range m.members[orgID] {
		out = append(out, repository.Member{UserID: uid, RoleID: role})
	}
	return out, nil
}

func (m *memOrgRepo) AddMemberByEmail(ctx context.Context, orgID uuid.UUID, email, roleID string, now time.Time) (*repository.Member, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	uid, ok := m.usersByMail[email]
	if !ok {
		return nil, repository.ErrUserNotFound
	}
	if _, exists := m.members[orgID][uid]; exists {
		return nil, repository.ErrMemberAlreadyExists
	}
	m.members[orgID][uid] = roleID
	return &repository.Member{UserID: uid, Email: email, RoleID: roleID, CreatedAt: now}, nil
}

func (m *memOrgRepo) UpdateMemberRole(ctx context.Context, orgID, targetUserID uuid.UUID, roleID string, now time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	current, ok := m.members[orgID][targetUserID]
	if !ok {
		return repository.ErrMemberNotFound
	}
	if current == "owner" && roleID != "owner" && m.ownerCount(orgID) <= 1 {
		return repository.ErrLastOwner
	}
	m.members[orgID][targetUserID] = roleID
	return nil
}

func (m *memOrgRepo) RemoveMember(ctx context.Context, orgID, targetUserID uuid.UUID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	current, ok := m.members[orgID][targetUserID]
	if !ok {
		return repository.ErrMemberNotFound
	}
	if current == "owner" && m.ownerCount(orgID) <= 1 {
		return repository.ErrLastOwner
	}
	delete(m.members[orgID], targetUserID)
	return nil
}

func (m *memOrgRepo) ownerCount(orgID uuid.UUID) int {
	n := 0
	for _, r := range m.members[orgID] {
		if r == "owner" {
			n++
		}
	}
	return n
}

func (m *memOrgRepo) CreateInvite(ctx context.Context, inv *repository.Invite) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := *inv
	m.invites[inv.TokenHash] = &cp
	return nil
}

func (m *memOrgRepo) AcceptInvite(ctx context.Context, userID uuid.UUID, tokenHash string, now time.Time) (*repository.Organization, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	inv, ok := m.invites[tokenHash]
	if !ok || inv.AcceptedAt != nil || inv.RevokedAt != nil || !now.Before(inv.ExpiresAt) {
		return nil, repository.ErrInvalidInviteToken
	}
	inv.AcceptedAt = &now
	existingRole, alreadyMember := m.members[inv.OrganizationID][userID]
	if !alreadyMember {
		m.members[inv.OrganizationID][userID] = inv.RoleID
		existingRole = inv.RoleID
	}
	cp := *m.orgs[inv.OrganizationID]
	cp.RoleID = existingRole
	return &cp, nil
}

func (m *memOrgRepo) RevokeInvite(ctx context.Context, orgID, inviteID uuid.UUID, now time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, inv := range m.invites {
		if inv.ID == inviteID && inv.OrganizationID == orgID && inv.AcceptedAt == nil {
			inv.RevokedAt = &now
			return nil
		}
	}
	return repository.ErrInviteNotFound
}

func (m *memOrgRepo) CreateAPIToken(ctx context.Context, tok *repository.APIToken) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := *tok
	m.tokens[tok.TokenHash] = &cp
	return nil
}

func (m *memOrgRepo) ListAPITokens(ctx context.Context, orgID uuid.UUID) ([]repository.APIToken, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []repository.APIToken
	for _, tok := range m.tokens {
		if tok.OrganizationID == orgID && tok.RevokedAt == nil {
			out = append(out, *tok)
		}
	}
	return out, nil
}

func (m *memOrgRepo) RevokeAPIToken(ctx context.Context, orgID, tokenID uuid.UUID, now time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, tok := range m.tokens {
		if tok.ID == tokenID && tok.OrganizationID == orgID {
			tok.RevokedAt = &now
			return nil
		}
	}
	return repository.ErrTokenNotFound
}

func (m *memOrgRepo) GetAPITokenByHash(ctx context.Context, tokenHash string) (*repository.APIToken, repository.Status, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	tok, ok := m.tokens[tokenHash]
	if !ok {
		return nil, "", repository.ErrTokenNotFound
	}
	cp := *tok
	return &cp, repository.StatusActive, nil
}

func (m *memOrgRepo) TouchAPITokenLastUsed(ctx context.Context, tokenID uuid.UUID, usedAt time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, tok := range m.tokens {
		if tok.ID == tokenID {
			tok.LastUsedAt = &usedAt
		}
	}
	return nil
}

func TestOrgRBACLastOwnerAndAPITokens(t *testing.T) {
	repo := newMemOrgRepo()
	svc := service.NewOrgService(repo)
	ctx := context.Background()

	ownerID := uuid.New()
	memberID := uuid.New()
	repo.usersByMail["dev@kr0n.dev"] = memberID

	// 1. CreateOrg sets creator as owner
	o, err := svc.CreateOrg(ctx, ownerID, "Acme Corp", "acme-corp")
	if err != nil || o.RoleID != "owner" {
		t.Fatalf("CreateOrg: %v, %+v", err, o)
	}
	ownerP := repository.Principal{UserID: ownerID, Kind: "session"}
	memberP := repository.Principal{UserID: memberID, Kind: "session"}

	// 2. Last owner cannot be removed or demoted
	if err := svc.UpdateMemberRole(ctx, ownerP, o.ID, ownerID, "admin"); !errors.Is(err, repository.ErrLastOwner) {
		t.Fatalf("expected ErrLastOwner on demoting sole owner, got %v", err)
	}
	if err := svc.RemoveMember(ctx, ownerP, o.ID, ownerID); !errors.Is(err, repository.ErrLastOwner) {
		t.Fatalf("expected ErrLastOwner on removing sole owner, got %v", err)
	}

	// 3. Add member and verify RBAC boundaries
	if _, err := svc.AddMember(ctx, ownerP, o.ID, "dev@kr0n.dev", "member"); err != nil {
		t.Fatalf("AddMember: %v", err)
	}
	if _, err := svc.GetOrg(ctx, memberP, o.ID); err != nil {
		t.Fatalf("member should have org:read: %v", err)
	}
	if err := svc.DeleteOrg(ctx, memberP, o.ID); !errors.Is(err, repository.ErrForbidden) {
		t.Fatalf("member must not have org:delete, got %v", err)
	}

	// 4. API tokens: format, permission subset check, validation, revocation
	if _, _, err := svc.CreateAPIToken(ctx, memberP, o.ID, "bad", []string{"org:read"}, 3600); !errors.Is(err, repository.ErrForbidden) {
		t.Fatalf("member without apitoken:create must fail, got %v", err)
	}

	tok, rawSecret, err := svc.CreateAPIToken(ctx, ownerP, o.ID, "ci-deployer", []string{"project:read", "project:create"}, 3600)
	if err != nil {
		t.Fatalf("CreateAPIToken: %v", err)
	}
	if !strings.HasPrefix(rawSecret, repository.APITokenPrefix) || tok.TokenHash == rawSecret {
		t.Fatalf("invalid token secret or hash: secret=%q hash=%q", rawSecret, tok.TokenHash)
	}

	validated, err := svc.ValidateAPIToken(ctx, rawSecret)
	if err != nil || validated.ID != tok.ID {
		t.Fatalf("ValidateAPIToken: %v %+v", err, validated)
	}

	// Token principal only has its granted subset in its org
	tokP := repository.Principal{
		UserID:           validated.CreatedByUserID,
		Kind:             "api_token",
		TokenOrgID:       &validated.OrganizationID,
		TokenPermissions: validated.Permissions,
	}
	if ok, _ := svc.Can(ctx, tokP, o.ID, "project:create"); !ok {
		t.Fatal("expected api_token principal to have project:create")
	}
	if ok, _ := svc.Can(ctx, tokP, o.ID, "org:delete"); ok {
		t.Fatal("api_token principal must NOT have org:delete outside its permission subset")
	}
	if ok, _ := svc.Can(ctx, tokP, uuid.New(), "project:create"); ok {
		t.Fatal("api_token principal must NOT be valid in another organization")
	}

	// Revoke API token -> subsequent ValidateAPIToken fails
	if err := svc.RevokeAPIToken(ctx, ownerP, o.ID, tok.ID); err != nil {
		t.Fatalf("RevokeAPIToken: %v", err)
	}
	if _, err := svc.ValidateAPIToken(ctx, rawSecret); !errors.Is(err, repository.ErrInvalidAPIToken) {
		t.Fatalf("expected ErrInvalidAPIToken after revoke, got %v", err)
	}

	// 5. Invites: create and accept
	inviteeID := uuid.New()
	inv, rawInviteTok, err := svc.CreateInvite(ctx, ownerP, o.ID, "invitee@kr0n.dev", "admin")
	if err != nil || inv.RoleID != "admin" {
		t.Fatalf("CreateInvite: %v %+v", err, inv)
	}
	joinedOrg, err := svc.AcceptInvite(ctx, inviteeID, rawInviteTok)
	if err != nil || joinedOrg.ID != o.ID || joinedOrg.RoleID != "admin" {
		t.Fatalf("AcceptInvite: %v %+v", err, joinedOrg)
	}
}
