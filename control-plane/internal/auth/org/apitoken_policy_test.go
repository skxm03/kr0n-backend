package org

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
)

// apiTokenFixture builds an org with an owner, an admin (token creator) and a member.
type apiTokenFixture struct {
	repo    *memRepo
	svc     *Service
	org     *Organization
	ownerP  Principal
	adminID uuid.UUID
	adminP  Principal
}

func newAPITokenFixture(t *testing.T) *apiTokenFixture {
	t.Helper()
	repo := newMemRepo()
	svc := NewService(repo)
	ownerID, adminID := uuid.New(), uuid.New()
	o, err := svc.CreateOrg(context.Background(), ownerID, "Acme", "acme")
	if err != nil {
		t.Fatalf("CreateOrg: %v", err)
	}
	repo.members[o.ID][adminID] = "admin"
	return &apiTokenFixture{
		repo: repo, svc: svc, org: o,
		ownerP:  Principal{UserID: ownerID, Kind: "session"},
		adminID: adminID,
		adminP:  Principal{UserID: adminID, Kind: "session"},
	}
}

// tokenPrincipal mirrors what the Auth gRPC layer builds from a validated token.
func tokenPrincipal(tok *APIToken) Principal {
	orgID := tok.OrganizationID
	return Principal{UserID: tok.CreatedByUserID, Kind: "api_token", TokenOrgID: &orgID, TokenPermissions: tok.Permissions}
}

func (f *apiTokenFixture) mint(t *testing.T, perms ...string) (*APIToken, string) {
	t.Helper()
	tok, raw, err := f.svc.CreateAPIToken(context.Background(), f.adminP, f.org.ID, "ci", perms, 3600)
	if err != nil {
		t.Fatalf("CreateAPIToken: %v", err)
	}
	return tok, raw
}

func TestAPIToken_WorksWhileCreatorIsAuthorizedMember(t *testing.T) {
	f := newAPITokenFixture(t)
	_, raw := f.mint(t, "project:read", "project:create")
	validated, err := f.svc.ValidateAPIToken(context.Background(), raw)
	if err != nil {
		t.Fatalf("ValidateAPIToken: %v", err)
	}
	if ok, err := f.svc.Can(context.Background(), tokenPrincipal(validated), f.org.ID, "project:create"); err != nil || !ok {
		t.Fatalf("token should be allowed project:create, ok=%v err=%v", ok, err)
	}
}

func TestAPIToken_RemovedCreatorLosesAccessImmediately(t *testing.T) {
	f := newAPITokenFixture(t)
	ctx := context.Background()
	tok, raw := f.mint(t, "project:read")
	p := tokenPrincipal(tok)

	// The fake repo deliberately does NOT revoke tokens on removal, so this exercises the
	// membership check in ValidateAPIToken/Can independent of the Postgres revoke-on-remove.
	if err := f.svc.RemoveMember(ctx, f.ownerP, f.org.ID, f.adminID); err != nil {
		t.Fatalf("RemoveMember: %v", err)
	}
	if _, err := f.svc.ValidateAPIToken(ctx, raw); !errors.Is(err, ErrInvalidAPIToken) {
		t.Fatalf("expected ErrInvalidAPIToken after creator removal, got %v", err)
	}
	// A principal that was already validated before the removal must also be denied by Can.
	if ok, _ := f.svc.Can(ctx, p, f.org.ID, "project:read"); ok {
		t.Fatal("removed creator's token principal must not pass Can")
	}
}

func TestAPIToken_DemotedCreatorLosesPermissionsRoleNoLongerGrants(t *testing.T) {
	f := newAPITokenFixture(t)
	ctx := context.Background()
	tok, raw := f.mint(t, "project:read", "project:create", "member:delete")
	p := tokenPrincipal(tok)

	if err := f.svc.UpdateMemberRole(ctx, f.ownerP, f.org.ID, f.adminID, "member"); err != nil {
		t.Fatalf("UpdateMemberRole: %v", err)
	}

	validated, err := f.svc.ValidateAPIToken(ctx, raw)
	if err != nil {
		t.Fatalf("token for a still-present member must validate: %v", err)
	}
	if len(validated.Permissions) != 1 || validated.Permissions[0] != "project:read" {
		t.Fatalf("effective permissions must narrow to the member role, got %v", validated.Permissions)
	}
	for _, perm := range []string{"project:create", "member:delete"} {
		if ok, _ := f.svc.Can(ctx, p, f.org.ID, perm); ok {
			t.Fatalf("demoted creator's token must not hold %s", perm)
		}
	}
	if ok, _ := f.svc.Can(ctx, p, f.org.ID, "project:read"); !ok {
		t.Fatal("permission still granted by both token and role must remain")
	}

	// Re-promotion never exceeds the token's explicit grants.
	if err := f.svc.UpdateMemberRole(ctx, f.ownerP, f.org.ID, f.adminID, "admin"); err != nil {
		t.Fatalf("re-promote: %v", err)
	}
	if ok, _ := f.svc.Can(ctx, p, f.org.ID, "org:update"); ok {
		t.Fatal("token must never gain permissions it was not explicitly granted")
	}
}

func TestAPIToken_RevokedAndExpiredFail(t *testing.T) {
	f := newAPITokenFixture(t)
	ctx := context.Background()

	revoked, rawRevoked := f.mint(t, "project:read")
	if err := f.svc.RevokeAPIToken(ctx, f.ownerP, f.org.ID, revoked.ID); err != nil {
		t.Fatalf("RevokeAPIToken: %v", err)
	}
	if _, err := f.svc.ValidateAPIToken(ctx, rawRevoked); !errors.Is(err, ErrInvalidAPIToken) {
		t.Fatalf("revoked token must fail, got %v", err)
	}

	expired, rawExpired := f.mint(t, "project:read")
	past := time.Now().Add(-time.Minute)
	f.repo.tokens[expired.TokenHash].ExpiresAt = &past
	if _, err := f.svc.ValidateAPIToken(ctx, rawExpired); !errors.Is(err, ErrInvalidAPIToken) {
		t.Fatalf("expired token must fail, got %v", err)
	}

	if _, err := f.svc.ValidateAPIToken(ctx, APITokenPrefix+"deadbeef"); !errors.Is(err, ErrInvalidAPIToken) {
		t.Fatalf("unknown token must fail, got %v", err)
	}
}

func TestAPIToken_CannotCrossOrganizationBoundary(t *testing.T) {
	f := newAPITokenFixture(t)
	ctx := context.Background()
	tok, _ := f.mint(t, "project:read")

	// Creator is also an admin in a second org; the token for org A must not work there.
	other, err := f.svc.CreateOrg(ctx, f.ownerP.UserID, "Other", "other")
	if err != nil {
		t.Fatalf("CreateOrg: %v", err)
	}
	f.repo.members[other.ID][f.adminID] = "admin"
	if ok, _ := f.svc.Can(ctx, tokenPrincipal(tok), other.ID, "project:read"); ok {
		t.Fatal("token for org A must not authorize operations on org B even if its creator is a member of B")
	}
}

func TestAPIToken_CannotMintTokens(t *testing.T) {
	f := newAPITokenFixture(t)
	ctx := context.Background()
	tok, _ := f.mint(t, "apitoken:create", "project:read")

	// Even with apitoken:create (token and creator role), a token may not mint another token,
	// whether equal, narrower or broader in scope.
	for _, perms := range [][]string{{"project:read"}, {"project:read", "project:create"}, {"org:update"}} {
		if _, _, err := f.svc.CreateAPIToken(ctx, tokenPrincipal(tok), f.org.ID, "child", perms, 0); !errors.Is(err, ErrForbidden) {
			t.Fatalf("token minting a token with %v must be forbidden, got %v", perms, err)
		}
	}
}

func TestAPIToken_UserCannotDelegateMoreThanTheyHold(t *testing.T) {
	f := newAPITokenFixture(t)
	// admin does not hold org:delete
	if _, _, err := f.svc.CreateAPIToken(context.Background(), f.adminP, f.org.ID, "x", []string{"org:delete"}, 0); !errors.Is(err, ErrForbidden) {
		t.Fatalf("delegating a permission the creator lacks must fail, got %v", err)
	}
	if _, _, err := f.svc.CreateAPIToken(context.Background(), f.adminP, f.org.ID, "x", nil, 0); !errors.Is(err, ErrInvalidAPIToken) {
		t.Fatalf("empty permission set must be rejected, got %v", err)
	}
}

// TestAPIToken_ConcurrentRemovalAndUse defines the race semantics: every use is either allowed
// (it observed the membership before removal) or rejected; once RemoveMember returns, all later
// uses are rejected. Real row-lock behaviour is covered by the PostgreSQL integration test.
func TestAPIToken_ConcurrentRemovalAndUse(t *testing.T) {
	f := newAPITokenFixture(t)
	ctx := context.Background()
	_, raw := f.mint(t, "project:read")

	var wg sync.WaitGroup
	removed := make(chan struct{})
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				if _, err := f.svc.ValidateAPIToken(ctx, raw); err != nil && !errors.Is(err, ErrInvalidAPIToken) {
					t.Errorf("unexpected error during concurrent use: %v", err)
					return
				}
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := f.svc.RemoveMember(ctx, f.ownerP, f.org.ID, f.adminID); err != nil {
			t.Errorf("RemoveMember: %v", err)
		}
		close(removed)
	}()
	wg.Wait()
	<-removed

	if _, err := f.svc.ValidateAPIToken(ctx, raw); !errors.Is(err, ErrInvalidAPIToken) {
		t.Fatalf("after removal completes, token must be rejected, got %v", err)
	}
}
