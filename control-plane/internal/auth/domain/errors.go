package domain

import (
	"errors"
	"fmt"
)

// User & Credential Errors
var (
	// ErrEmailAlreadyExists indicates an account is already registered with the given email.
	ErrEmailAlreadyExists = errors.New("email already registered")

	// ErrInvalidEmail indicates the email address violates syntax or length rules.
	ErrInvalidEmail = errors.New("invalid email address")

	// ErrInvalidPassword indicates the password violates policy rules.
	ErrInvalidPassword = errors.New("invalid password")

	// ErrInvalidDisplayName indicates the display name is empty or exceeds limits.
	ErrInvalidDisplayName = errors.New("display name must not be empty")

	// ErrUserNotFound indicates no user entity was found for the given criteria.
	ErrUserNotFound = errors.New("user not found")

	// ErrInvalidCredentials indicates incorrect email or password.
	ErrInvalidCredentials = errors.New("invalid email or password")

	// ErrUserNotActive indicates the user account is suspended or deactivated.
	ErrUserNotActive = errors.New("user account is not active")

	// ErrEmailNotVerified indicates login requires a verified email address.
	ErrEmailNotVerified = errors.New("email address is not verified")

	// ErrInvalidResetToken indicates a password reset token is invalid, expired, or already used.
	ErrInvalidResetToken = errors.New("invalid or expired password reset token")

	// ErrOAuthEmailNotVerified indicates the OAuth provider did not supply a verified email address.
	ErrOAuthEmailNotVerified = errors.New("oauth email address is not verified")

	// ErrOAuthAccountConflict indicates the user account is already linked to a different identity for the provider.
	ErrOAuthAccountConflict = errors.New("account is already linked to another oauth identity")
)

// Session & Refresh Token Errors
var (
	// ErrSessionNotFound indicates the requested session does not exist.
	ErrSessionNotFound = errors.New("session not found")

	// ErrSessionExpired indicates the session is past its expiration time.
	ErrSessionExpired = errors.New("session expired")

	// ErrSessionRevoked indicates the session has been revoked.
	ErrSessionRevoked = errors.New("session revoked")

	// ErrInvalidRefreshToken indicates the provided refresh token is invalid.
	ErrInvalidRefreshToken = errors.New("invalid refresh token")
)

// Verification & Password Reset Token Errors
var (
	// ErrInvalidToken indicates the verification token is invalid, malformed, or missing.
	ErrInvalidToken = errors.New("invalid or expired verification token")

	// ErrTokenExpired indicates the verification token has expired.
	// Wraps ErrInvalidToken to allow callers to match generically.
	ErrTokenExpired = fmt.Errorf("%w: token expired", ErrInvalidToken)

	// ErrTokenAlreadyConsumed indicates the verification token was previously consumed.
	// Wraps ErrInvalidToken to prevent revealing token usage history.
	ErrTokenAlreadyConsumed = fmt.Errorf("%w: token already consumed", ErrInvalidToken)

	// ErrResendLimitExceeded indicates the user has reached the maximum allowed verification resend requests per day.
	ErrResendLimitExceeded = errors.New("resend verification limit reached")
)

// Organization, Membership & RBAC Errors
var (
	// ErrOrgNotFound indicates the organization was not found.
	ErrOrgNotFound = errors.New("organization not found")

	// ErrSlugAlreadyExists indicates the organization slug is taken.
	ErrSlugAlreadyExists = errors.New("organization slug already exists")

	// ErrInvalidOrg indicates the organization name or slug is invalid.
	ErrInvalidOrg = errors.New("invalid organization name or slug")

	// ErrInvalidRole indicates an unapproved or unknown RBAC role was provided.
	ErrInvalidRole = errors.New("invalid role")

	// ErrForbidden indicates insufficient RBAC permissions for the action.
	ErrForbidden = errors.New("insufficient permissions")

	// ErrLastOwner indicates an action would remove or demote the sole owner of an organization.
	ErrLastOwner = errors.New("cannot remove or demote the last organization owner")

	// ErrMemberNotFound indicates the user is not a member of the organization.
	ErrMemberNotFound = errors.New("organization member not found")

	// ErrMemberAlreadyExists indicates the user already belongs to the organization.
	ErrMemberAlreadyExists = errors.New("user is already a member of this organization")

	// ErrInviteNotFound indicates the organization invite was not found.
	ErrInviteNotFound = errors.New("organization invite not found")

	// ErrInvalidInviteToken indicates the invitation token is invalid or expired.
	ErrInvalidInviteToken = errors.New("invalid or expired organization invite token")

	// ErrTokenNotFound indicates the API token was not found.
	ErrTokenNotFound = errors.New("api token not found")

	// ErrInvalidAPIToken indicates the provided API token is invalid or malformed.
	ErrInvalidAPIToken = errors.New("invalid api token")

	// ErrInstallationNotFound indicates the GitHub App installation was not found.
	ErrInstallationNotFound = errors.New("github installation not found")

	// ErrInstallationAlreadyLinked indicates the GitHub App installation is already bound to another org.
	ErrInstallationAlreadyLinked = errors.New("github installation is already linked to another organization")
)
