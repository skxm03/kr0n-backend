package service

import (
	"context"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/skxm03/kr0n-backend/control-plane/internal/auth/domain"
	"github.com/skxm03/kr0n-backend/control-plane/internal/auth/repository"
	pkgAudit "github.com/skxm03/kr0n-backend/control-plane/pkg/audit"
)

// AuditOption configures optional dependencies on AuditService.
type AuditOption func(*AuditService)

// AuditRecorder defines the contract for recording append-only audit events from domain operations.
type AuditRecorder interface {
	Record(ctx context.Context, ev domain.AuditEvent) error
}

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
func (s *AuditService) Record(ctx context.Context, ev domain.AuditEvent) error {
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
	case domain.ActorTypeUser, domain.ActorTypeAPIToken, domain.ActorTypeSystem:
	default:
		ev.ActorType = domain.ActorTypeUser
	}
	if ev.Metadata == nil {
		ev.Metadata = map[string]any{}
	} else {
		ev.Metadata = pkgAudit.RedactMetadata(ev.Metadata)
	}

	if ev.IPAddress == nil || ev.UserAgent == nil {
		clientCtx := pkgAudit.ExtractClientContext(ctx)
		if ev.IPAddress == nil && clientCtx.IPAddress != nil {
			ev.IPAddress = clientCtx.IPAddress
		}
		if ev.UserAgent == nil && clientCtx.UserAgent != nil {
			ev.UserAgent = clientCtx.UserAgent
		}
		if clientCtx.RequestID != "" {
			if _, exists := ev.Metadata["request_id"]; !exists {
				ev.Metadata["request_id"] = clientCtx.RequestID
			}
		}
	}

	status := strings.ToLower(strings.TrimSpace(ev.Status))
	if status == "" {
		act := strings.ToLower(ev.Action)
		if strings.Contains(act, "failed") || strings.Contains(act, "failure") {
			status = pkgAudit.StatusFailure
		} else if strings.Contains(act, "denied") {
			status = pkgAudit.StatusDenied
		} else {
			status = pkgAudit.StatusSuccess
		}
	}
	ev.Status = status

	if s.emitter != nil {
		reqID, _ := ev.Metadata["request_id"].(string)
		return s.emitter.Emit(ctx, pkgAudit.Event{
			ID:             ev.ID,
			Service:        "auth",
			Action:         ev.Action,
			Status:         status,
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
func (s *AuditService) ListByOrg(ctx context.Context, orgID uuid.UUID, action string, limit, offset int) ([]domain.AuditEvent, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}
	return s.repo.ListByOrg(ctx, orgID, action, limit, offset)
}
