package authz

import (
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"

	authv1 "github.com/skxm03/kr0n-backend/control-plane/gen/auth/v1"
	"github.com/skxm03/kr0n-backend/control-plane/pkg/grpcauth"
)

// Principal represents an authenticated subject across all control-plane services.
type Principal struct {
	UserID           uuid.UUID
	SessionID        *uuid.UUID
	Kind             string // "session", "api_token", "service"
	TokenOrgID       *uuid.UUID
	TokenPermissions []string
}

// FromCallerPrincipal converts a protobuf CallerPrincipal to an authz.Principal.
func FromCallerPrincipal(c *authv1.CallerPrincipal) (Principal, error) {
	if c == nil || strings.TrimSpace(c.GetUserId()) == "" {
		return Principal{}, errors.New("caller principal is empty")
	}
	uid, err := uuid.Parse(strings.TrimSpace(c.GetUserId()))
	if err != nil {
		return Principal{}, fmt.Errorf("invalid caller user_id: %w", err)
	}
	p := Principal{
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
	return p, nil
}

// FromPassport converts a grpcauth.Passport extracted from transport headers into a Principal.
func FromPassport(pass grpcauth.Passport) Principal {
	return Principal{
		UserID:           pass.UserID,
		Kind:             pass.Kind,
		TokenOrgID:       pass.OrgID,
		SessionID:        pass.SessionID,
		TokenPermissions: pass.Permissions,
	}
}

// HasPermission reports whether permission exists in perms.
func HasPermission(perms []string, permission string) bool {
	for _, p := range perms {
		if p == permission {
			return true
		}
	}
	return false
}
