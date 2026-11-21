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
					"description":    "Core engine repository",
					"language":       "Go",
					"updated_at":     "2026-11-20T10:00:00Z",
					"pushed_at":      "2026-11-20T10:30:00Z",
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
	if len(repos) != 1 || repos[0].FullName != "kr0n/kr0n-core" || repos[0].Owner != "kr0n" || repos[0].UpdatedAt != "2026-11-20T10:00:00Z" || repos[0].PushedAt != "2026-11-20T10:30:00Z" {
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

	dirsWithPresets, presets, err := c.ListDirectoriesWithPresets(ctx, "any-tok", "kr0n", "repo", "main")
	if err != nil {
		t.Fatalf("ListDirectoriesWithPresets: %v", err)
	}
	if len(dirsWithPresets) != len(want) {
		t.Fatalf("expected %d dirs with presets, got %d", len(want), len(dirsWithPresets))
	}
	if presets["/apps/api"] != "go" {
		t.Fatalf("expected preset for /apps/api to be 'go', got %q", presets["/apps/api"])
	}
	if presets["/apps"] != "" {
		t.Fatalf("expected preset for /apps to be empty (no build strategy), got %q", presets["/apps"])
	}
}

func TestClient_DetectPresetFromFiles(t *testing.T) {
	cases := []struct {
		name     string
		files    []string
		expected string
	}{
		{"empty", []string{}, ""},
		{"no strategy (assets)", []string{"banner.png", "logo.svg", "README.md"}, ""},
		{"nextjs config", []string{"next.config.mjs", "package.json"}, "nextjs"},
		{"vite config", []string{"vite.config.ts", "package.json"}, "vite"},
		{"go module", []string{"go.mod", "main.go"}, "go"},
		{"python requirements", []string{"requirements.txt", "server.py"}, "python"},
		{"rust cargo", []string{"Cargo.toml", "src/main.rs"}, "rust"},
		{"ruby gemfile", []string{"Gemfile"}, "ruby"},
		{"php composer", []string{"composer.json"}, "php"},
		{"java pom", []string{"pom.xml"}, "java"},
		{"dotnet project", []string{"app.csproj"}, "dotnet"},
		{"dockerfile", []string{"Dockerfile"}, "dockerfile"},
		{"plain node", []string{"package.json", "index.js"}, "nodejs"},
		{"static site", []string{"index.html", "style.css"}, "static"},
	}

	for _, tc := range cases {
		got := client.DetectPresetFromFiles(tc.files)
		if got != tc.expected {
			t.Errorf("DetectPresetFromFiles(%s): expected %q, got %q", tc.name, tc.expected, got)
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
