package repository

import (
	"github.com/skxm03/kr0n-backend/control-plane/internal/auth/domain"
)

// Domain errors re-exported from internal/auth/domain.
var (
	// User & Credential Errors
	ErrEmailAlreadyExists    = domain.ErrEmailAlreadyExists
	ErrInvalidEmail          = domain.ErrInvalidEmail
	ErrInvalidPassword       = domain.ErrInvalidPassword
	ErrInvalidDisplayName    = domain.ErrInvalidDisplayName
	ErrUserNotFound          = domain.ErrUserNotFound
	ErrInvalidCredentials    = domain.ErrInvalidCredentials
	ErrUserNotActive         = domain.ErrUserNotActive
	ErrEmailNotVerified      = domain.ErrEmailNotVerified
	ErrInvalidResetToken     = domain.ErrInvalidResetToken
	ErrOAuthEmailNotVerified = domain.ErrOAuthEmailNotVerified
	ErrOAuthAccountConflict  = domain.ErrOAuthAccountConflict

	// Session & Refresh Token Errors
	ErrSessionNotFound     = domain.ErrSessionNotFound
	ErrSessionExpired      = domain.ErrSessionExpired
	ErrSessionRevoked      = domain.ErrSessionRevoked
	ErrInvalidRefreshToken = domain.ErrInvalidRefreshToken

	// Verification & Password Reset Token Errors
	ErrInvalidToken          = domain.ErrInvalidToken
	ErrTokenExpired          = domain.ErrTokenExpired
	ErrTokenAlreadyConsumed  = domain.ErrTokenAlreadyConsumed
	ErrResendLimitExceeded   = domain.ErrResendLimitExceeded

	// Organization, Membership & RBAC Errors
	ErrOrgNotFound               = domain.ErrOrgNotFound
	ErrSlugAlreadyExists         = domain.ErrSlugAlreadyExists
	ErrInvalidOrg                = domain.ErrInvalidOrg
	ErrInvalidRole               = domain.ErrInvalidRole
	ErrForbidden                 = domain.ErrForbidden
	ErrLastOwner                 = domain.ErrLastOwner
	ErrMemberNotFound            = domain.ErrMemberNotFound
	ErrMemberAlreadyExists       = domain.ErrMemberAlreadyExists
	ErrInviteNotFound            = domain.ErrInviteNotFound
	ErrInvalidInviteToken        = domain.ErrInvalidInviteToken
	ErrTokenNotFound             = domain.ErrTokenNotFound
	ErrInvalidAPIToken           = domain.ErrInvalidAPIToken
	ErrInstallationNotFound      = domain.ErrInstallationNotFound
	ErrInstallationAlreadyLinked = domain.ErrInstallationAlreadyLinked
)
