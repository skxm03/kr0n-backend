package sinks

import (
	"context"
	"io"
	"log/slog"
	"os"

	pkgAudit "github.com/skxm03/kr0n-backend/control-plane/pkg/audit"
)

// LoggerSink writes structured JSON audit events to a slog.Logger (stdout by default)
// for log shippers such as Vector, FluentBit, or Datadog Agent.
type LoggerSink struct {
	logger *slog.Logger
}

// NewLoggerSink creates a structured JSON LoggerSink writing to w (defaults to os.Stdout if nil).
func NewLoggerSink(w io.Writer) *LoggerSink {
	if w == nil {
		w = os.Stdout
	}
	return &LoggerSink{
		logger: slog.New(slog.NewJSONHandler(w, nil)),
	}
}

func (s *LoggerSink) Name() string {
	return "logger"
}

func (s *LoggerSink) WriteBatch(ctx context.Context, events []pkgAudit.Event) error {
	for i := range events {
		ev := events[i]
		orgID := ""
		if ev.OrganizationID != nil {
			orgID = ev.OrganizationID.String()
		}
		actorID := ""
		if ev.Actor.UserID != nil {
			actorID = ev.Actor.UserID.String()
		}
		ip := ""
		if ev.ClientContext.IPAddress != nil {
			ip = ev.ClientContext.IPAddress.String()
		}
		ua := ""
		if ev.ClientContext.UserAgent != nil {
			ua = *ev.ClientContext.UserAgent
		}

		s.logger.InfoContext(ctx, "audit_event",
			slog.String("id", ev.ID.String()),
			slog.String("service", ev.Service),
			slog.String("action", ev.Action),
			slog.String("status", ev.Status),
			slog.String("organization_id", orgID),
			slog.String("actor_user_id", actorID),
			slog.String("actor_type", ev.Actor.Type),
			slog.String("target_type", ev.Target.Type),
			slog.String("target_id", ev.Target.ID),
			slog.String("ip_address", ip),
			slog.String("user_agent", ua),
			slog.String("request_id", ev.ClientContext.RequestID),
			slog.Time("timestamp", ev.Timestamp),
			slog.Any("metadata", ev.Metadata),
		)
	}
	return nil
}

func (s *LoggerSink) Close() error {
	return nil
}
