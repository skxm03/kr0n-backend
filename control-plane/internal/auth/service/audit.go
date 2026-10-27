package service

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/skxm03/kr0n-backend/control-plane/internal/auth/repository"
)

// AuditService records and queries append-only audit events.
type AuditService struct {
	repo repository.AuditRepository
}

// NewAuditService creates a new AuditService.
func NewAuditService(repo repository.AuditRepository) *AuditService {
	return &AuditService{repo: repo}
}

// Record appends an audit event. Missing ID/CreatedAt/ActorType are populated with safe defaults.
func (s *AuditService) Record(ctx context.Context, ev repository.AuditEvent) error {
	if s == nil || s.repo == nil {
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
	return s.repo.Insert(ctx, ev)
}

// ListByOrg returns audit events for an organization ordered newest-first.
func (s *AuditService) ListByOrg(ctx context.Context, orgID uuid.UUID, limit, offset int) ([]repository.AuditEvent, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}
	return s.repo.ListByOrg(ctx, orgID, limit, offset)
}
