package service

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/skxm03/kr0n-backend/control-plane/internal/auth/repository"
	pkgAudit "github.com/skxm03/kr0n-backend/control-plane/pkg/audit"
)

// AuditOption configures optional dependencies on AuditService.
type AuditOption func(*AuditService)

// WithAuditEmitter configures an asynchronous RabbitMQ audit emitter for Record calls.
// When set, audit events are emitted to the audit message broker instead of synchronously writing to Postgres.
func WithAuditEmitter(emitter pkgAudit.Emitter) AuditOption {
	return func(s *AuditService) {
		s.emitter = emitter
	}
}

// AuditService records and queries append-only audit events.
type AuditService struct {
	repo    repository.AuditRepository
	emitter pkgAudit.Emitter
}

// NewAuditService creates a new AuditService with optional emitter configuration.
func NewAuditService(repo repository.AuditRepository, opts ...AuditOption) *AuditService {
	svc := &AuditService{repo: repo}
	for _, opt := range opts {
		if opt != nil {
			opt(svc)
		}
	}
	return svc
}

// Record appends an audit event. Missing ID/CreatedAt/ActorType are populated with safe defaults.
// If an audit Emitter is configured, the event is published to the audit RabbitMQ broker;
// otherwise it falls back to inserting directly via the repository.
func (s *AuditService) Record(ctx context.Context, ev repository.AuditEvent) error {
	if s == nil || (s.repo == nil && s.emitter == nil) {
		return nil
	}
	if ev.ID == uuid.Nil {
		id, err := uuid.NewV7()
		if err != nil {
			id = uuid.New()
		}
		ev.ID = id
	}
	if ev.CreatedAt.IsZero() {
		ev.CreatedAt = time.Now().UTC()
	}
	switch ev.ActorType {
	case repository.ActorTypeUser, repository.ActorTypeAPIToken, repository.ActorTypeSystem:
	default:
		ev.ActorType = repository.ActorTypeUser
	}
	if ev.Metadata == nil {
		ev.Metadata = map[string]any{}
	}

	if s.emitter != nil {
		reqID, _ := ev.Metadata["request_id"].(string)
		return s.emitter.Emit(ctx, pkgAudit.Event{
			ID:             ev.ID,
			Service:        "auth",
			Action:         ev.Action,
			Status:         pkgAudit.StatusSuccess,
			OrganizationID: ev.OrganizationID,
			Actor: pkgAudit.Actor{
				UserID: ev.ActorUserID,
				Type:   ev.ActorType,
			},
			Target: pkgAudit.Target{
				Type: ev.ResourceType,
				ID:   ev.ResourceID,
			},
			ClientContext: pkgAudit.ClientContext{
				IPAddress: ev.IPAddress,
				UserAgent: ev.UserAgent,
				RequestID: reqID,
			},
			Metadata:  ev.Metadata,
			Timestamp: ev.CreatedAt,
		})
	}

	return s.repo.Insert(ctx, ev)
}

// ListByOrg returns audit events for an organization ordered newest-first.
func (s *AuditService) ListByOrg(ctx context.Context, orgID uuid.UUID, action string, limit, offset int) ([]repository.AuditEvent, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}
	return s.repo.ListByOrg(ctx, orgID, action, limit, offset)
}
