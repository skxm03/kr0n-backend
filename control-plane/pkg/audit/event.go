package audit

import (
	"errors"
	"net"
	"strings"
	"time"

	"github.com/google/uuid"
)

const (
	// SchemaVersion identifies the canonical audit event envelope schema version.
	SchemaVersion = "1.0"

	// Actor types matching database constraints on audit_events.actor_type.
	ActorTypeUser     = "user"
	ActorTypeAPIToken = "api_token"
	ActorTypeSystem   = "system"

	// Outcome status values.
	StatusSuccess = "success"
	StatusFailure = "failure"
	StatusDenied  = "denied"
)

var (
	ErrMissingAction       = errors.New("audit: action is required")
	ErrMissingTargetType   = errors.New("audit: target.type is required")
	ErrMissingService      = errors.New("audit: service is required")
	ErrInvalidActorType    = errors.New("audit: actor.type must be one of user, api_token, system")
)

// Actor identifies who performed the audited operation.
type Actor struct {
	UserID *uuid.UUID `json:"user_id,omitempty"`
	Type   string     `json:"type"`
	Name   string     `json:"name,omitempty"`
}

// Target identifies the domain resource affected by the operation.
type Target struct {
	Type string `json:"type"`
	ID   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
}

// ClientContext captures network and tracing metadata for the request.
type ClientContext struct {
	IPAddress *net.IP `json:"ip_address,omitempty"`
	UserAgent *string `json:"user_agent,omitempty"`
	RequestID string  `json:"request_id,omitempty"`
	TraceID   string  `json:"trace_id,omitempty"`
}

// Event is the canonical, immutable audit event envelope emitted across all kr0n services.
type Event struct {
	ID             uuid.UUID      `json:"id"`
	Version        string         `json:"version"`
	Service        string         `json:"service"`
	Action         string         `json:"action"`
	Status         string         `json:"status"`
	OrganizationID *uuid.UUID     `json:"organization_id,omitempty"`
	Actor          Actor          `json:"actor"`
	Target         Target         `json:"target"`
	ClientContext  ClientContext  `json:"client_context"`
	Metadata       map[string]any `json:"metadata,omitempty"`
	Timestamp      time.Time      `json:"timestamp"`
}

// Normalize populates safe defaults for missing envelope fields.
func (e *Event) Normalize(defaultService string) {
	if e.ID == uuid.Nil {
		if id, err := uuid.NewV7(); err == nil {
			e.ID = id
		} else {
			e.ID = uuid.New()
		}
	}
	if strings.TrimSpace(e.Version) == "" {
		e.Version = SchemaVersion
	}
	e.Service = strings.TrimSpace(e.Service)
	if e.Service == "" {
		e.Service = strings.TrimSpace(defaultService)
	}
	e.Action = strings.TrimSpace(e.Action)
	e.Target.Type = strings.TrimSpace(e.Target.Type)
	e.Target.ID = strings.TrimSpace(e.Target.ID)
	e.Status = strings.ToLower(strings.TrimSpace(e.Status))
	switch e.Status {
	case StatusSuccess, StatusFailure, StatusDenied:
	default:
		e.Status = StatusSuccess
	}
	e.Actor.Type = strings.ToLower(strings.TrimSpace(e.Actor.Type))
	switch e.Actor.Type {
	case ActorTypeUser, ActorTypeAPIToken, ActorTypeSystem:
	default:
		e.Actor.Type = ActorTypeUser
	}
	if e.Timestamp.IsZero() {
		e.Timestamp = time.Now().UTC()
	} else {
		e.Timestamp = e.Timestamp.UTC()
	}
	if e.Metadata == nil {
		e.Metadata = map[string]any{}
	}
}

// Validate checks required invariants on the audit event envelope.
func (e Event) Validate() error {
	if strings.TrimSpace(e.Service) == "" {
		return ErrMissingService
	}
	if strings.TrimSpace(e.Action) == "" {
		return ErrMissingAction
	}
	if strings.TrimSpace(e.Target.Type) == "" {
		return ErrMissingTargetType
	}
	switch e.Actor.Type {
	case ActorTypeUser, ActorTypeAPIToken, ActorTypeSystem:
	default:
		return ErrInvalidActorType
	}
	return nil
}

// RoutingKey returns the AMQP topic routing key in the format `<prefix>.<service>.<action>`.
func (e Event) RoutingKey(prefix string) string {
	p := sanitizeSegment(prefix)
	if p == "" {
		p = DefaultRoutingKeyPrefix
	}
	svc := sanitizeSegment(e.Service)
	if svc == "" {
		svc = "unknown"
	}
	act := sanitizeAction(e.Action)
	if act == "" {
		act = "unknown"
	}
	return p + "." + svc + "." + act
}

func sanitizeSegment(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.ReplaceAll(s, " ", "_")
	s = strings.ReplaceAll(s, ".", "_")
	return s
}

func sanitizeAction(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.ReplaceAll(s, " ", "_")
	return strings.Trim(s, ".")
}
