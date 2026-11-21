package sinks

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	pkgAudit "github.com/skxm03/kr0n-backend/control-plane/pkg/audit"
)

// PostgresSink persists audit event batches into the append-only PostgreSQL `audit_events` table.
// It uses `ON CONFLICT (id) DO NOTHING` to ensure strict idempotency under at-least-once RabbitMQ delivery.
type PostgresSink struct {
	pool    *pgxpool.Pool
	ownPool bool
}

// NewPostgresSink wraps an existing pgxpool.Pool as an audit sink.
func NewPostgresSink(pool *pgxpool.Pool, ownPool bool) *PostgresSink {
	return &PostgresSink{
		pool:    pool,
		ownPool: ownPool,
	}
}

func (s *PostgresSink) Name() string {
	return "postgres"
}

const insertAuditEventSQL = `
	INSERT INTO audit_events (
		id, organization_id, actor_user_id, actor_type, action,
		resource_type, resource_id, ip_address, user_agent, metadata, created_at
	) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10::jsonb, $11)
	ON CONFLICT (id) DO NOTHING
`

// WriteBatch inserts all events in a single PostgreSQL pipelined batch round-trip.
func (s *PostgresSink) WriteBatch(ctx context.Context, events []pkgAudit.Event) error {
	if len(events) == 0 {
		return nil
	}
	if s == nil || s.pool == nil {
		return fmt.Errorf("postgres sink: pool is not initialized")
	}

	batch := &pgx.Batch{}
	for i := range events {
		ev := events[i]
		meta := enrichMetadata(ev)
		metaBytes, err := json.Marshal(meta)
		if err != nil || len(metaBytes) == 0 || string(metaBytes) == "null" {
			metaBytes = []byte(`{}`)
		}

		var ipStr *string
		if ev.ClientContext.IPAddress != nil && len(*ev.ClientContext.IPAddress) > 0 {
			ip := ev.ClientContext.IPAddress.String()
			ipStr = &ip
		}

		var resID *string
		if trimmed := strings.TrimSpace(ev.Target.ID); trimmed != "" {
			resID = &trimmed
		}

		batch.Queue(
			insertAuditEventSQL,
			ev.ID,
			ev.OrganizationID,
			ev.Actor.UserID,
			ev.Actor.Type,
			ev.Action,
			ev.Target.Type,
			resID,
			ipStr,
			ev.ClientContext.UserAgent,
			string(metaBytes),
			ev.Timestamp,
		)
	}

	br := s.pool.SendBatch(ctx, batch)
	defer br.Close()

	for i := 0; i < len(events); i++ {
		if _, err := br.Exec(); err != nil {
			return fmt.Errorf("postgres sink batch exec (index=%d id=%s): %w", i, events[i].ID, err)
		}
	}

	return nil
}

func (s *PostgresSink) Close() error {
	if s != nil && s.ownPool && s.pool != nil {
		s.pool.Close()
	}
	return nil
}

func enrichMetadata(ev pkgAudit.Event) map[string]any {
	out := make(map[string]any, len(ev.Metadata)+6)
	for k, v := range ev.Metadata {
		out[k] = v
	}
	if ev.Service != "" {
		if _, exists := out["service"]; !exists {
			out["service"] = ev.Service
		}
	}
	if ev.Status != "" {
		if _, exists := out["status"]; !exists {
			out["status"] = ev.Status
		}
	}
	if ev.Actor.Name != "" {
		if _, exists := out["actor_name"]; !exists {
			out["actor_name"] = ev.Actor.Name
		}
	}
	if ev.Target.Name != "" {
		if _, exists := out["target_name"]; !exists {
			out["target_name"] = ev.Target.Name
		}
	}
	if ev.ClientContext.RequestID != "" {
		if _, exists := out["request_id"]; !exists {
			out["request_id"] = ev.ClientContext.RequestID
		}
	}
	if ev.ClientContext.TraceID != "" {
		if _, exists := out["trace_id"]; !exists {
			out["trace_id"] = ev.ClientContext.TraceID
		}
	}
	return out
}
