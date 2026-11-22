package domain

import (
	"net"
	"time"

	"github.com/google/uuid"
)

// Status represents the operational state of a user account.
type Status string

const (
	StatusActive      Status = "active"
	StatusSuspended   Status = "suspended"
	StatusDeactivated Status = "deactivated"
)

// User represents the authoritative user domain entity.
type User struct {
	ID                  uuid.UUID
	Email               string
	DisplayName         string
	AvatarURL           *string
	Status              Status
	EmailVerifiedAt     *time.Time
	FailedLoginAttempts int
	LockedUntil         *time.Time
	CreatedAt           time.Time
	UpdatedAt           time.Time
}

// OAuthProfile represents a verified identity returned by an OAuth provider.
type OAuthProfile struct {
	Provider       string
	ProviderUserID string
	Email          string
	EmailVerified  bool
	DisplayName    string
	AvatarURL      *string
}

// Session represents an authenticated user session.
type Session struct {
	ID         uuid.UUID
	UserID     uuid.UUID
	TokenHash  string
	UserAgent  *string
	IPAddress  *net.IP
	ExpiresAt  time.Time
	RevokedAt  *time.Time
	CreatedAt  time.Time
	LastSeenAt time.Time
}

// Token represents an email verification or password reset token entity.
type Token struct {
	ID         uuid.UUID
	UserID     uuid.UUID
	TokenHash  string
	ExpiresAt  time.Time
	ConsumedAt *time.Time
	CreatedAt  time.Time
}

// Principal represents an authenticated caller evaluated by the authorization service.
type Principal struct {
	UserID           uuid.UUID
	Kind             string // "session" or "api_token"
	TokenOrgID       *uuid.UUID
	TokenPermissions []string
	SessionID        *uuid.UUID
}

// Organization represents a tenant organization domain entity.
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

// Invite represents an organization invitation entity.
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

// APIToken represents an organization-scoped API token.
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

// GitHubInstallation represents a GitHub App installation bound to an Organization.
type GitHubInstallation struct {
	ID                  uuid.UUID
	OrganizationID      uuid.UUID
	InstallationID      int64
	AccountLogin        string
	AccountType         string
	RepositorySelection string
	Status              string
	CreatedByUserID     uuid.UUID
	CreatedAt           time.Time
	UpdatedAt           time.Time
}

const (
	ActorTypeUser     = "user"
	ActorTypeAPIToken = "api_token"
	ActorTypeSystem   = "system"

	OutboxStatusPending    = "pending"
	OutboxStatusProcessing = "processing"
	OutboxStatusPublished  = "published"
	OutboxStatusFailed     = "failed"

	EventTypeEmailVerification = "email.verify_email"
	EventTypePasswordReset     = "email.password_reset"
	EventTypeOrgInvite         = "email.org_invite"
)

// AuditEvent represents an immutable audit log entry.
type AuditEvent struct {
	ID             uuid.UUID
	OrganizationID *uuid.UUID
	ActorUserID    *uuid.UUID
	ActorType      string
	Action         string
	Status         string
	ResourceType   string
	ResourceID     string
	IPAddress      *net.IP
	UserAgent      *string
	Metadata       map[string]any
	CreatedAt      time.Time
}

// OutboxEvent represents an atomic transactional outbox message.
type OutboxEvent struct {
	ID            uuid.UUID
	EventType     string
	AggregateType string
	AggregateID   uuid.UUID
	Payload       map[string]any
	Headers       map[string]any
	Status        string
	RetryCount    int
	LastError     *string
	CreatedAt     time.Time
	ScheduledAt   time.Time
	PublishedAt   *time.Time
}
