package middleware

import (
	"testing"
)

func TestGroupMatchRule_Exact(t *testing.T) {
	rule := GroupMatchRule{
		Path:    "/api/v1/auth/login",
		Type:    MatchExact,
		Methods: map[string]bool{"POST": true},
	}

	if !rule.Matches("POST", "/api/v1/auth/login") {
		t.Errorf("expected exact match to succeed")
	}
	if !rule.Matches("POST", "/api/v1/auth/login/") {
		t.Errorf("expected exact match with trailing slash to succeed")
	}
	if rule.Matches("GET", "/api/v1/auth/login") {
		t.Errorf("expected GET to fail method check")
	}
	if rule.Matches("POST", "/api/v1/auth/register") {
		t.Errorf("expected different path to fail")
	}
}

func TestGroupMatchRule_Prefix(t *testing.T) {
	rule := GroupMatchRule{
		Path: "/api/v1/orgs/*",
		Type: MatchPrefix,
	}

	if !rule.Matches("GET", "/api/v1/orgs") {
		t.Errorf("expected base prefix to match")
	}
	if !rule.Matches("POST", "/api/v1/orgs/123/members") {
		t.Errorf("expected sub-path to match")
	}
	if rule.Matches("GET", "/api/v1/other") {
		t.Errorf("expected unrelated path to fail")
	}
}

func TestGroupMatchRule_Template(t *testing.T) {
	rule := GroupMatchRule{
		Path: "/api/v1/users/{id}/settings",
		Type: MatchTemplate,
	}

	if !rule.Matches("GET", "/api/v1/users/user_123/settings") {
		t.Errorf("expected template match to succeed")
	}
	if rule.Matches("GET", "/api/v1/users/user_123/profile") {
		t.Errorf("expected different tail to fail")
	}
	if rule.Matches("GET", "/api/v1/users/user_123/settings/sub") {
		t.Errorf("expected different segment length to fail")
	}
}
