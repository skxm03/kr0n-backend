package repository

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	ActorTypeUser     = "user"
	ActorTypeAPIToken = "api_token"
	ActorTypeSystem   = "system"
)

// AuditEvent represents an immutable audit log entry in `audit_events`.
type AuditEvent struct {
	ID             uuid.UUID
	OrganizationID *uuid.UUID
	ActorUserID    *uuid.UUID
	ActorType      string
	Action         string
	ResourceType   string
	ResourceID     string
	IPAddress      *net.IP
	UserAgent      *string
	Metadata       map[string]any
	CreatedAt      time.Time
}

// AuditRepository defines storage operations for append-only audit events.
type AuditRepository interface {
	Insert(ctx context.Context, ev AuditEvent) error
	ListByOrg(ctx context.Context, orgID uuid.UUID, limit, offset int) ([]AuditEvent, error)
}

// PostgresAuditRepository implements AuditRepository using PostgreSQL (`audit_events` append-only table).
type PostgresAuditRepository struct {
	pool *pgxpool.Pool
}

// NewPostgresAuditRepository creates a new PostgresAuditRepository for audit events.
func NewPostgresAuditRepository(pool *pgxpool.Pool) *PostgresAuditRepository {
	return &PostgresAuditRepository{pool: pool}
}

// Insert appends a single audit event row.
func (r *PostgresAuditRepository) Insert(ctx context.Context, ev AuditEvent) error {
	metaBytes, err := json.Marshal(ev.Metadata)
	if err != nil || len(metaBytes) == 0 || string(metaBytes) == "null" {
		metaBytes = []byte(`{}`)
	}
	var ipStr *string
	if ev.IPAddress != nil && len(*ev.IPAddress) > 0 {
		s := ev.IPAddress.String()
		ipStr = &s
	}
	var resID *string
	if trimmed := strings.TrimSpace(ev.ResourceID); trimmed != "" {
		resID = &trimmed
	}
	_, err = r.pool.Exec(ctx, `
		INSERT INTO audit_events (
			id, organization_id, actor_user_id, actor_type, action,
			resource_type, resource_id, ip_address, user_agent, metadata, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10::jsonb, $11)
	`, ev.ID, ev.OrganizationID, ev.ActorUserID, ev.ActorType, ev.Action,
		ev.ResourceType, resID, ipStr, ev.UserAgent, string(metaBytes), ev.CreatedAt)
	if err != nil {
		return fmt.Errorf("insert audit event: %w", err)
	}
	return nil
}

// ListByOrg queries organization audit events ordered by created_at DESC.
func (r *PostgresAuditRepository) ListByOrg(ctx context.Context, orgID uuid.UUID, limit, offset int) ([]AuditEvent, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT id, organization_id, actor_user_id, actor_type, action,
		       resource_type, COALESCE(resource_id, ''), host(ip_address), user_agent, metadata, created_at
		FROM audit_events
		WHERE organization_id = $1
		ORDER BY created_at DESC
		LIMIT $2 OFFSET $3
	`, orgID, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("list audit events: %w", err)
	}
	defer rows.Close()

	var out []AuditEvent
	for rows.Next() {
		var (
			ev       AuditEvent
			ipStr    *string
			metaJSON []byte
		)
		if err := rows.Scan(
			&ev.ID,
			&ev.OrganizationID,
			&ev.ActorUserID,
			&ev.ActorType,
			&ev.Action,
			&ev.ResourceType,
			&ev.ResourceID,
			&ipStr,
			&ev.UserAgent,
			&metaJSON,
			&ev.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan audit event: %w", err)
		}
		if ipStr != nil {
			if parsed := net.ParseIP(*ipStr); parsed != nil {
				ev.IPAddress = &parsed
			}
		}
		ev.Metadata = map[string]any{}
		if len(metaJSON) > 0 {
			_ = json.Unmarshal(metaJSON, &ev.Metadata)
		}
		out = append(out, ev)
	}
	return out, rows.Err()
}
