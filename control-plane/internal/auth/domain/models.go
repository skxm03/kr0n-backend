package domain

import (
	"net"
	"time"

	"github.com/google/uuid"

	"github.com/skxm03/kr0n-backend/control-plane/pkg/authz"
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
type Principal = authz.Principal

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

// DomainEvent represents a typed business event that can produce an atomic transactional outbox message.
type DomainEvent interface {
	EventType() string
	AggregateType() string
	AggregateID() uuid.UUID
	ToOutboxEvent(now time.Time) *OutboxEvent
}

func (e *OutboxEvent) ToOutboxEvent(_ time.Time) *OutboxEvent { return e }

// EmailVerificationEvent is emitted when a user requires email verification.
type EmailVerificationEvent struct {
	UserID   uuid.UUID
	Email    string
	RawToken string
}

func (e EmailVerificationEvent) EventType() string      { return EventTypeEmailVerification }
func (e EmailVerificationEvent) AggregateType() string  { return "user" }
func (e EmailVerificationEvent) AggregateID() uuid.UUID { return e.UserID }
func (e EmailVerificationEvent) ToOutboxEvent(now time.Time) *OutboxEvent {
	return NewEmailOutboxEvent(e.UserID, "user", EventTypeEmailVerification, "verify_email", e.Email, map[string]string{
		"token": e.RawToken,
	}, now)
}

// PasswordResetEvent is emitted when a user requests password reset instructions.
type PasswordResetEvent struct {
	UserID   uuid.UUID
	Email    string
	RawToken string
}

func (e PasswordResetEvent) EventType() string      { return EventTypePasswordReset }
func (e PasswordResetEvent) AggregateType() string  { return "user" }
func (e PasswordResetEvent) AggregateID() uuid.UUID { return e.UserID }
func (e PasswordResetEvent) ToOutboxEvent(now time.Time) *OutboxEvent {
	return NewEmailOutboxEvent(e.UserID, "user", EventTypePasswordReset, "password_reset", e.Email, map[string]string{
		"token": e.RawToken,
	}, now)
}

// OrgInviteEvent is emitted when an invitation to join an organization is created.
type OrgInviteEvent struct {
	OrgID    uuid.UUID
	OrgName  string
	Email    string
	RoleID   string
	RawToken string
}

func (e OrgInviteEvent) EventType() string      { return EventTypeOrgInvite }
func (e OrgInviteEvent) AggregateType() string  { return "organization" }
func (e OrgInviteEvent) AggregateID() uuid.UUID { return e.OrgID }
func (e OrgInviteEvent) ToOutboxEvent(now time.Time) *OutboxEvent {
	return NewEmailOutboxEvent(e.OrgID, "organization", EventTypeOrgInvite, "org_invite", e.Email, map[string]string{
		"org_name": e.OrgName,
		"role_id":  e.RoleID,
		"token":    e.RawToken,
	}, now)
}

// NewEmailOutboxEvent encapsulates standard email job payload formatting for OutboxEvent.
func NewEmailOutboxEvent(
	aggregateID uuid.UUID,
	aggregateType string,
	eventType string,
	templateType string,
	recipient string,
	data map[string]string,
	now time.Time,
) *OutboxEvent {
	id, err := uuid.NewV7()
	if err != nil {
		id = uuid.New()
	}
	jobID, err := uuid.NewV7()
	if err != nil {
		jobID = uuid.New()
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	return &OutboxEvent{
		ID:            id,
		EventType:     eventType,
		AggregateType: aggregateType,
		AggregateID:   aggregateID,
		Payload: map[string]any{
			"id":         jobID.String(),
			"type":       templateType,
			"recipient":  recipient,
			"data":       data,
			"created_at": now.Format(time.RFC3339),
		},
		Headers:     map[string]any{},
		Status:      OutboxStatusPending,
		CreatedAt:   now,
		ScheduledAt: now,
	}
}
