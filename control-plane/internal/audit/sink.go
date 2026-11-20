package audit

import (
	"context"
	"strings"

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

const redactedPlaceholder = "[REDACTED]"

var defaultSensitiveKeys = map[string]struct{}{
	"password":       {},
	"password_hash":  {},
	"secret":         {},
	"client_secret":  {},
	"token":          {},
	"access_token":   {},
	"refresh_token":  {},
	"api_key":        {},
	"apikey":         {},
	"private_key":    {},
	"authorization":  {},
	"cookie":         {},
	"set-cookie":     {},
	"session_secret": {},
}

// RedactSensitiveMetadataTransformer returns an EventTransformer that recursively scrubs
// sensitive keys (passwords, secrets, tokens, private keys) from Event.Metadata before persistence.
func RedactSensitiveMetadataTransformer(extraKeys ...string) EventTransformer {
	sensitive := make(map[string]struct{}, len(defaultSensitiveKeys)+len(extraKeys))
	for k := range defaultSensitiveKeys {
		sensitive[k] = struct{}{}
	}
	for _, k := range extraKeys {
		normalized := strings.ToLower(strings.TrimSpace(k))
		if normalized != "" {
			sensitive[normalized] = struct{}{}
		}
	}

	return func(ev pkgAudit.Event) (pkgAudit.Event, error) {
		if len(ev.Metadata) > 0 {
			ev.Metadata = redactMap(ev.Metadata, sensitive)
		}
		return ev, nil
	}
}

func redactMap(in map[string]any, sensitive map[string]struct{}) map[string]any {
	out := make(map[string]any, len(in))
	for k, v := range in {
		normalized := strings.ToLower(strings.TrimSpace(k))
		if _, isSensitive := sensitive[normalized]; isSensitive {
			out[k] = redactedPlaceholder
			continue
		}
		if nested, ok := v.(map[string]any); ok {
			out[k] = redactMap(nested, sensitive)
			continue
		}
		out[k] = v
	}
	return out
}
