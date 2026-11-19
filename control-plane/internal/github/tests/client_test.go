package tests

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/skxm03/kr0n-backend/control-plane/internal/github/client"
)

func TestClient_ListRepositories_SuccessAndCaching(t *testing.T) {
	var httpCalls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		httpCalls.Add(1)
		if r.Header.Get("Authorization") != "Bearer test-tok" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"repositories": []map[string]any{
				{
					"id":             101,
					"name":           "kr0n-core",
					"full_name":      "kr0n/kr0n-core",
					"private":        true,
					"default_branch": "main",
					"html_url":       "https://github.com/kr0n/kr0n-core",
					"owner": map[string]any{
						"login": "kr0n",
					},
				},
			},
		})
	}))
	defer server.Close()

	c := client.NewHTTPClient(
		server.URL,
		client.WithCacheTTL(10*time.Second),
		client.WithHTTPClient(server.Client()),
	)

	ctx := context.Background()
	repos, err := c.ListRepositories(ctx, "test-tok")
	if err != nil {
		t.Fatalf("ListRepositories: %v", err)
	}
	if len(repos) != 1 || repos[0].FullName != "kr0n/kr0n-core" || repos[0].Owner != "kr0n" {
		t.Fatalf("unexpected repos: %+v", repos)
	}

	// Second call with same token should hit cache
	repos2, err := c.ListRepositories(ctx, "test-tok")
	if err != nil {
		t.Fatalf("ListRepositories cached: %v", err)
	}
	if len(repos2) != 1 {
		t.Fatalf("expected 1 cached repo")
	}
	if got := httpCalls.Load(); got != 1 {
		t.Fatalf("expected 1 HTTP call due to cache, got %d", got)
	}
}

func TestClient_ListBranches_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/repos/kr0n/kr0n-core/branches" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode([]map[string]any{
			{
				"name":      "main",
				"protected": true,
				"commit": map[string]any{
					"sha": "abcdef123",
				},
			},
			{
				"name":      "feat/feature-x",
				"protected": false,
				"commit": map[string]any{
					"sha": "987654321",
				},
			},
		})
	}))
	defer server.Close()

	c := client.NewHTTPClient(server.URL, client.WithHTTPClient(server.Client()))
	ctx := context.Background()

	branches, err := c.ListBranches(ctx, "any-tok", "kr0n", "kr0n-core")
	if err != nil {
		t.Fatalf("ListBranches: %v", err)
	}
	if len(branches) != 2 || branches[0].Name != "main" || !branches[0].Protected || branches[0].CommitSHA != "abcdef123" {
		t.Fatalf("unexpected branches: %+v", branches)
	}
}

func TestClient_ListDirectories_Filtering(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("recursive") != "1" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"sha": "tree-sha",
			"tree": []map[string]any{
				{"path": "README.md", "type": "blob"},
				{"path": "apps", "type": "tree"},
				{"path": "apps/api", "type": "tree"},
				{"path": "apps/api/main.go", "type": "blob"},
				{"path": "apps/web", "type": "tree"},
				{"path": "node_modules", "type": "tree"},
				{"path": "node_modules/pkg", "type": "tree"},
				{"path": "vendor", "type": "tree"},
				{"path": "vendor/github.com", "type": "tree"},
				{"path": ".github", "type": "tree"},
				{"path": ".github/workflows", "type": "tree"},
			},
		})
	}))
	defer server.Close()

	c := client.NewHTTPClient(server.URL, client.WithHTTPClient(server.Client()))
	ctx := context.Background()

	dirs, err := c.ListDirectories(ctx, "any-tok", "kr0n", "repo", "main")
	if err != nil {
		t.Fatalf("ListDirectories: %v", err)
	}

	// Should include root "/" and non-hidden subtrees, excluding .github, node_modules, and vendor
	want := []string{"/", "/apps", "/apps/api", "/apps/web"}
	if len(dirs) != len(want) {
		t.Fatalf("expected dirs %v, got %v", want, dirs)
	}
	for i := range want {
		if dirs[i] != want[i] {
			t.Fatalf("expected dir[%d]=%q, got %q", i, want[i], dirs[i])
		}
	}
}

func TestClient_ErrorHandling(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		wantErr    error
	}{
		{"unauthorized", http.StatusUnauthorized, client.ErrUnauthorized},
		{"not_found", http.StatusNotFound, client.ErrNotFound},
		{"rate_limit_403", http.StatusForbidden, client.ErrRateLimited},
		{"rate_limit_429", http.StatusTooManyRequests, client.ErrRateLimited},
		{"server_error", http.StatusInternalServerError, client.ErrUpstream},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.statusCode)
			}))
			defer server.Close()

			c := client.NewHTTPClient(server.URL, client.WithHTTPClient(server.Client()))
			_, err := c.ListRepositories(context.Background(), "tok")
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("expected error %v, got %v", tt.wantErr, err)
			}
		})
	}
}
