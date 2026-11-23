package tests

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
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
	if presets["/apps/api"] != "golang" {
		t.Fatalf("expected preset for /apps/api to be 'golang', got %q", presets["/apps/api"])
	}
	if presets["/apps"] != "other" {
		t.Fatalf("expected preset for /apps to be 'other', got %q", presets["/apps"])
	}
}

func TestClient_DetectPresetFromFiles(t *testing.T) {
	cases := []struct {
		name     string
		files    []string
		expected string
	}{
		{"empty", []string{}, "other"},
		{"no strategy (assets)", []string{"banner.png", "logo.svg", "README.md"}, "other"},
		{"nextjs config", []string{"next.config.mjs", "package.json"}, "nextjs"},
		{"vite config", []string{"vite.config.ts", "package.json"}, "vite"},
		{"go module", []string{"go.mod", "main.go"}, "golang"},
		{"python requirements", []string{"requirements.txt", "server.py"}, "other"},
		{"rust cargo", []string{"Cargo.toml", "src/main.rs"}, "other"},
		{"ruby gemfile", []string{"Gemfile"}, "other"},
		{"php composer", []string{"composer.json"}, "other"},
		{"java pom", []string{"pom.xml"}, "other"},
		{"dotnet project", []string{"app.csproj"}, "other"},
		{"dockerfile", []string{"Dockerfile"}, "other"},
		{"plain node without vite/next", []string{"package.json", "index.js"}, "other"},
		{"static site", []string{"index.html", "style.css"}, "other"},
		{"vite with index.html and package.json", []string{"index.html", "package.json"}, "vite"},
	}

	for _, tc := range cases {
		got := client.DetectPresetFromFiles(tc.files)
		if got != tc.expected {
			t.Errorf("DetectPresetFromFiles(%s): expected %q, got %q", tc.name, tc.expected, got)
		}
	}
}

func TestClient_DetectFramework_DeepInspectionAndLockfiles(t *testing.T) {
	// 1. Next.js with pnpm
	pnpmNext := client.DetectFramework([]string{"next.config.ts", "package.json", "pnpm-lock.yaml"}, nil)
	if pnpmNext.Framework != "nextjs" || pnpmNext.SuggestedInstallCommand != "pnpm install" || pnpmNext.SuggestedBuildCommand != "pnpm run build" || pnpmNext.SuggestedRunCommand != "pnpm start" {
		t.Fatalf("unexpected pnpm nextjs result: %+v", pnpmNext)
	}

	// 2. Vite with yarn
	yarnVite := client.DetectFramework([]string{"vite.config.js", "package.json", "yarn.lock"}, nil)
	if yarnVite.Framework != "vite" || yarnVite.SuggestedInstallCommand != "yarn install" || yarnVite.SuggestedBuildCommand != "yarn build" || yarnVite.SuggestedRunCommand != "yarn preview" {
		t.Fatalf("unexpected yarn vite result: %+v", yarnVite)
	}

	// 3. Vite with bun
	bunVite := client.DetectFramework([]string{"vite.config.mjs", "package.json", "bun.lockb"}, nil)
	if bunVite.Framework != "vite" || bunVite.SuggestedInstallCommand != "bun install" || bunVite.SuggestedRunCommand != "bun run preview" {
		t.Fatalf("unexpected bun vite result: %+v", bunVite)
	}

	// 4. Golang commands
	goRes := client.DetectFramework([]string{"go.mod", "main.go"}, nil)
	if goRes.Framework != "golang" || goRes.SuggestedInstallCommand != "go mod download" || goRes.SuggestedBuildCommand != "go build -o out/app ./..." || goRes.SuggestedRunCommand != "./out/app" {
		t.Fatalf("unexpected golang result: %+v", goRes)
	}

	// 5. Ambiguous package.json deep inspection: Next.js dependency
	nextPkg := []byte(`{"dependencies": {"next": "^14.0.0", "react": "^18.2.0"}}`)
	deepNext := client.DetectFramework([]string{"package.json"}, func() ([]byte, error) {
		return nextPkg, nil
	})
	if deepNext.Framework != "nextjs" || deepNext.SuggestedInstallCommand != "npm install" || deepNext.SuggestedRunCommand != "npm start" {
		t.Fatalf("unexpected deep inspection nextjs result: %+v", deepNext)
	}

	// 6. Ambiguous package.json deep inspection: Vite in devDependencies
	vitePkg := []byte(`{"devDependencies": {"vite": "^5.0.0"}}`)
	deepVite := client.DetectFramework([]string{"package.json"}, func() ([]byte, error) {
		return vitePkg, nil
	})
	if deepVite.Framework != "vite" || deepVite.SuggestedOutputDirectory != "dist" {
		t.Fatalf("unexpected deep inspection vite result: %+v", deepVite)
	}

	// 7. Ambiguous package.json deep inspection: Vite in scripts
	viteScriptPkg := []byte(`{"scripts": {"build": "vite build"}}`)
	deepScriptVite := client.DetectFramework([]string{"package.json"}, func() ([]byte, error) {
		return viteScriptPkg, nil
	})
	if deepScriptVite.Framework != "vite" {
		t.Fatalf("unexpected deep inspection vite scripts result: %+v", deepScriptVite)
	}

	// 8. Other dependency (e.g. Express)
	expressPkg := []byte(`{"dependencies": {"express": "^4.18.0"}}`)
	deepExpress := client.DetectFramework([]string{"package.json"}, func() ([]byte, error) {
		return expressPkg, nil
	})
	if deepExpress.Framework != "other" {
		t.Fatalf("expected 'other' for express package, got %s", deepExpress.Framework)
	}
}

func TestClient_ExploreDirectory_LazyExploration(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/git/trees/") {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"sha": "tree-sha",
				"tree": []map[string]any{
					{"path": "go.mod", "type": "blob", "sha": "sha-go-mod"},
					{"path": "main.go", "type": "blob", "sha": "sha-main-go"},
					{"path": "apps", "type": "tree", "sha": "sha-apps"},
					{"path": "apps/web", "type": "tree", "sha": "sha-web"},
					{"path": "apps/web/package.json", "type": "blob", "sha": "sha-pkg-json"},
					{"path": "apps/web/vite.config.ts", "type": "blob", "sha": "sha-vite-cfg"},
					{"path": "apps/api", "type": "tree", "sha": "sha-api"},
					{"path": "apps/api/go.mod", "type": "blob", "sha": "sha-api-go"},
				},
			})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	c := client.NewHTTPClient(server.URL, client.WithHTTPClient(server.Client()))
	ctx := context.Background()

	// 1. Explore root "/"
	rootRes, err := c.ExploreDirectory(ctx, "tok", "kr0n", "repo", "main", "/")
	if err != nil {
		t.Fatalf("ExploreDirectory root: %v", err)
	}
	if rootRes.CurrentDirectory.Path != "/" || rootRes.CurrentDirectory.DetectedPreset != "golang" {
		t.Fatalf("expected root to be golang, got %+v", rootRes.CurrentDirectory)
	}
	if !rootRes.CurrentDirectory.HasChildren {
		t.Fatalf("expected root to have children")
	}
	if len(rootRes.Children) != 1 || rootRes.Children[0].Path != "/apps" {
		t.Fatalf("expected children of / to be [/apps], got %+v", rootRes.Children)
	}

	// 2. Explore "/apps"
	appsRes, err := c.ExploreDirectory(ctx, "tok", "kr0n", "repo", "main", "/apps")
	if err != nil {
		t.Fatalf("ExploreDirectory /apps: %v", err)
	}
	if appsRes.CurrentDirectory.Path != "/apps" || appsRes.CurrentDirectory.DetectedPreset != "other" {
		t.Fatalf("expected /apps to be other, got %+v", appsRes.CurrentDirectory)
	}
	if len(appsRes.Children) != 2 || appsRes.Children[0].Path != "/apps/api" || appsRes.Children[1].Path != "/apps/web" {
		t.Fatalf("expected children [/apps/api, /apps/web], got %+v", appsRes.Children)
	}
	if appsRes.Children[1].DetectedPreset != "vite" {
		t.Fatalf("expected /apps/web preset to be vite, got %s", appsRes.Children[1].DetectedPreset)
	}

	// 3. Explore non-existent path
	_, err = c.ExploreDirectory(ctx, "tok", "kr0n", "repo", "main", "/non-existent")
	if !errors.Is(err, client.ErrNotFound) {
		t.Fatalf("expected ErrNotFound for non-existent directory, got %v", err)
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
