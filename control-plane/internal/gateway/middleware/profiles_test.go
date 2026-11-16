package middleware

import (
	"testing"
)

func TestProfileResolver_Resolve(t *testing.T) {
	profiles := map[string][]MiddlewareItem{
		"base": {
			{Name: "request_id"},
			{Name: "recovery"},
		},
		"authenticated": {
			{Name: "base"}, // references base profile
			{Name: "authentication"},
		},
	}

	resolver, err := NewProfileResolver(profiles)
	if err != nil {
		t.Fatalf("failed to create resolver: %v", err)
	}

	items, err := resolver.Resolve([]string{"authenticated"})
	if err != nil {
		t.Fatalf("failed to resolve profile: %v", err)
	}

	if len(items) != 3 {
		t.Fatalf("expected 3 items, got %d", len(items))
	}
	if items[0].Name != "request_id" || items[1].Name != "recovery" || items[2].Name != "authentication" {
		t.Errorf("unexpected profile items order: %+v", items)
	}
}

func TestProfileResolver_DetectsCycle(t *testing.T) {
	profiles := map[string][]MiddlewareItem{
		"a": {{Name: "b"}},
		"b": {{Name: "a"}},
	}

	_, err := NewProfileResolver(profiles)
	if err == nil {
		t.Fatalf("expected error detecting cycle, got nil")
	}
}
