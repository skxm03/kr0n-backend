package audit

import (
	"strings"
)

// RedactedPlaceholder is the string substituted for sensitive keys.
const RedactedPlaceholder = "[REDACTED]"

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

// RedactMetadata recursively scrubs sensitive keys from metadata.
func RedactMetadata(in map[string]any, extraKeys ...string) map[string]any {
	if in == nil {
		return map[string]any{}
	}
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
	return redactMap(in, sensitive)
}

func redactMap(in map[string]any, sensitive map[string]struct{}) map[string]any {
	out := make(map[string]any, len(in))
	for k, v := range in {
		normalized := strings.ToLower(strings.TrimSpace(k))
		if _, isSensitive := sensitive[normalized]; isSensitive {
			out[k] = RedactedPlaceholder
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
