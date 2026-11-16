package middleware

import (
	"testing"

	"gopkg.in/yaml.v3"
)

func TestMiddlewareItem_UnmarshalYAML(t *testing.T) {
	yamlData := `
- request_id
- recovery
- rate_limit:
    requests: 100
    window: 1m
- cors:
    allow_credentials: true
    allowed_origins:
      - "https://example.com"
`
	var items []MiddlewareItem
	if err := yaml.Unmarshal([]byte(yamlData), &items); err != nil {
		t.Fatalf("failed to unmarshal yaml: %v", err)
	}

	if len(items) != 4 {
		t.Fatalf("expected 4 items, got %d", len(items))
	}

	if items[0].Name != "request_id" || items[0].Config != nil {
		t.Errorf("item 0 unexpected: %+v", items[0])
	}
	if items[1].Name != "recovery" || items[1].Config != nil {
		t.Errorf("item 1 unexpected: %+v", items[1])
	}
	if items[2].Name != "rate_limit" || items[2].Config == nil {
		t.Errorf("item 2 unexpected: %+v", items[2])
	}
	if items[2].Config["requests"] != 100 {
		t.Errorf("item 2 config 'requests' expected 100, got %v", items[2].Config["requests"])
	}
	if items[3].Name != "cors" || items[3].Config == nil {
		t.Errorf("item 3 unexpected: %+v", items[3])
	}
}
