package authz

import (
	"context"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	authv1 "github.com/skxm03/kr0n-backend/control-plane/gen/auth/v1"
	"github.com/skxm03/kr0n-backend/control-plane/pkg/grpcauth"
)

// Authorizer evaluates whether caller principal p holds permission in orgID.
type Authorizer interface {
	CheckPermission(ctx context.Context, p Principal, orgID uuid.UUID, permission string) (bool, error)
}

// Can evaluates whether caller principal p holds permission in orgID.
// It verifies:
// 1. Non-nil IDs and non-empty permission name.
// 2. For API tokens: token must be scoped to orgID and explicitly grant permission.
// 3. For sessions and users: evaluates against the provided Authorizer (membership & role permissions).
func Can(ctx context.Context, a Authorizer, p Principal, orgID uuid.UUID, permission string) (bool, error) {
	if p.UserID == uuid.Nil || orgID == uuid.Nil || permission == "" {
		return false, nil
	}
	if p.Kind == "api_token" {
		if p.TokenOrgID == nil || *p.TokenOrgID != orgID || !HasPermission(p.TokenPermissions, permission) {
			return false, nil
		}
	}

	if a != nil {
		return a.CheckPermission(ctx, p, orgID, permission)
	}
	return false, nil
}

// AuthClientAuthorizer evaluates permissions by calling AuthService.CheckPermission over gRPC.
type AuthClientAuthorizer struct {
	client authv1.AuthServiceClient
}

// NewAuthClientAuthorizer creates an Authorizer backed by an AuthService gRPC client.
func NewAuthClientAuthorizer(client authv1.AuthServiceClient) *AuthClientAuthorizer {
	return &AuthClientAuthorizer{client: client}
}

func (a *AuthClientAuthorizer) CheckPermission(ctx context.Context, p Principal, orgID uuid.UUID, permission string) (bool, error) {
	resp, err := a.client.CheckPermission(ctx, &authv1.CheckPermissionRequest{
		Caller: &authv1.CallerPrincipal{
			UserId: p.UserID.String(),
			Kind:   p.Kind,
		},
		OrgId:      orgID.String(),
		Permission: permission,
	})
	if err != nil {
		return false, err
	}
	return resp.GetAllowed(), nil
}

// LocalDBAuthorizer evaluates permissions directly against PostgreSQL using an optimized single-query index join.
type LocalDBAuthorizer struct {
	pool *pgxpool.Pool
}

// NewLocalDBAuthorizer creates a LocalDBAuthorizer backed by a pgxpool.Pool.
func NewLocalDBAuthorizer(pool *pgxpool.Pool) *LocalDBAuthorizer {
	return &LocalDBAuthorizer{pool: pool}
}

func (a *LocalDBAuthorizer) CheckPermission(ctx context.Context, p Principal, orgID uuid.UUID, permission string) (bool, error) {
	var allowed bool
	err := a.pool.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1
			FROM organization_memberships om
			JOIN role_permissions rp ON om.role_id = rp.role_id
			WHERE om.organization_id = $1
			  AND om.user_id = $2
			  AND rp.permission_id = $3
		);
	`, orgID, p.UserID, permission).Scan(&allowed)
	if err != nil {
		return false, fmt.Errorf("check membership permission: %w", err)
	}
	return allowed, nil
}

// ParseOrgCall validates service transport auth, extracts caller passport or proto principal,
// and parses the target orgID into an authz.Principal and uuid.UUID.
func ParseOrgCall(
	ctx context.Context,
	cfg grpcauth.ServiceAuthConfig,
	c *authv1.CallerPrincipal,
	rawOrgID string,
) (Principal, uuid.UUID, error) {
	if cfg.Enabled && !grpcauth.IsTrustedService(ctx) {
		return Principal{}, uuid.Nil, status.Error(codes.Unauthenticated, "caller principal rejected: untrusted service boundary")
	}

	var pass grpcauth.Passport
	var hasMetadataPass bool
	if grpcauth.IsTrustedService(ctx) {
		pass, hasMetadataPass = grpcauth.ExtractPassportMetadata(ctx)
	}

	orgID, err := uuid.Parse(strings.TrimSpace(rawOrgID))
	if err != nil {
		if hasMetadataPass && pass.OrgID != nil {
			orgID = *pass.OrgID
		} else {
			return Principal{}, uuid.Nil, status.Error(codes.InvalidArgument, "invalid org_id")
		}
	}

	if c != nil && strings.TrimSpace(c.GetUserId()) != "" {
		p, err := FromCallerPrincipal(c)
		if err != nil {
			return Principal{}, uuid.Nil, status.Error(codes.InvalidArgument, err.Error())
		}
		return p, orgID, nil
	}

	if hasMetadataPass {
		return FromPassport(pass), orgID, nil
	}

	return Principal{}, uuid.Nil, status.Error(codes.Unauthenticated, "authentication required: missing caller passport")
}
