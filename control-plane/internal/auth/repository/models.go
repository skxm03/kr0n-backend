package repository

import (
	"github.com/skxm03/kr0n-backend/control-plane/internal/auth/domain"
)

// Domain model type aliases re-exported from internal/auth/domain.
type Status = domain.Status

const (
	StatusActive      = domain.StatusActive
	StatusSuspended   = domain.StatusSuspended
	StatusDeactivated = domain.StatusDeactivated
)

type User = domain.User
type OAuthProfile = domain.OAuthProfile
type Session = domain.Session
type Token = domain.Token
type Principal = domain.Principal
type Organization = domain.Organization
type Member = domain.Member
type Invite = domain.Invite
type Role = domain.Role
type APIToken = domain.APIToken

const (
	ActorTypeUser     = domain.ActorTypeUser
	ActorTypeAPIToken = domain.ActorTypeAPIToken
	ActorTypeSystem   = domain.ActorTypeSystem

	OutboxStatusPending    = domain.OutboxStatusPending
	OutboxStatusProcessing = domain.OutboxStatusProcessing
	OutboxStatusPublished  = domain.OutboxStatusPublished
	OutboxStatusFailed     = domain.OutboxStatusFailed

	EventTypeEmailVerification = domain.EventTypeEmailVerification
	EventTypePasswordReset     = domain.EventTypePasswordReset
	EventTypeOrgInvite         = domain.EventTypeOrgInvite
)

type AuditEvent = domain.AuditEvent
type OutboxEvent = domain.OutboxEvent

// Re-exported token helpers from internal/auth/domain.
var (
	GenerateToken   = domain.GenerateToken
	HashToken       = domain.HashToken
	VerifyTokenHash = domain.VerifyToken
)
