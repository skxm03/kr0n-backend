package audit

import (
	"context"

	pkgAudit "github.com/skxm03/kr0n-backend/control-plane/pkg/audit"
)

// Sink persists or forwards a batch of validated audit events.
// Sinks must be thread-safe and idempotent with respect to event IDs.
type Sink interface {
	Name() string
	WriteBatch(ctx context.Context, events []pkgAudit.Event) error
	Close() error
}

// EventTransformer enriches, filters, or scrubs an audit event before it is dispatched to sinks.
// Returning an error rejects the event and routes the delivery to the dead-letter queue.
type EventTransformer func(ev pkgAudit.Event) (pkgAudit.Event, error)

const redactedPlaceholder = pkgAudit.RedactedPlaceholder

// RedactSensitiveMetadataTransformer returns an EventTransformer that recursively scrubs
// sensitive keys (passwords, secrets, tokens, private keys) from Event.Metadata before persistence.
func RedactSensitiveMetadataTransformer(extraKeys ...string) EventTransformer {
	return func(ev pkgAudit.Event) (pkgAudit.Event, error) {
		if len(ev.Metadata) > 0 {
			ev.Metadata = pkgAudit.RedactMetadata(ev.Metadata, extraKeys...)
		}
		return ev, nil
	}
}
