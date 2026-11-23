package client

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"sort"
	"strings"
	"sync"
	"time"
)

// Repository represents repository metadata returned by GitHub.
type Repository struct {
	ID            int64  `json:"id"`
	Owner         string `json:"owner"`
	Name          string `json:"name"`
	FullName      string `json:"full_name"`
	Private       bool   `json:"private"`
	DefaultBranch string `json:"default_branch"`
	HTMLURL       string `json:"html_url"`
	Description   string `json:"description"`
	Language      string `json:"language"`
	UpdatedAt     string `json:"updated_at"`
	PushedAt      string `json:"pushed_at"`
}

// Branch represents branch metadata returned by GitHub.
type Branch struct {
	Name      string `json:"name"`
	CommitSHA string `json:"commit_sha"`
	Protected bool   `json:"protected"`
}

// DirectoryInfo represents details of a discovered directory with framework detection and suggested commands.
type DirectoryInfo struct {
	Path                     string
	Name                     string
	ParentPath               string
	DetectedPreset           string
	SuggestedInstallCommand  string
	SuggestedBuildCommand    string
	SuggestedRunCommand      string
	SuggestedOutputDirectory string
	HasChildren              bool
}

// DirectoryDiscoveryResult stores discovered directories, detected presets, and lazy exploration results.
type DirectoryDiscoveryResult struct {
	CurrentDirectory DirectoryInfo
	Children         []DirectoryInfo
	Directories      []string
	Presets          map[string]string
}

// FrameworkDetectionResult contains the detected framework identifier and suggested build commands.
type FrameworkDetectionResult struct {
	Framework                string // "nextjs" | "vite" | "golang" | "other"
	SuggestedInstallCommand  string
	SuggestedBuildCommand    string
	SuggestedRunCommand      string
	SuggestedOutputDirectory string
}

// Client defines the contract for communicating with GitHub REST endpoints.
type Client interface {
	ListRepositories(ctx context.Context, token string) ([]Repository, error)
	ListBranches(ctx context.Context, token string, owner, repo string) ([]Branch, error)
	ListDirectories(ctx context.Context, token string, owner, repo, ref string) ([]string, error)
	ListDirectoriesWithPresets(ctx context.Context, token string, owner, repo, ref string) ([]string, map[string]string, error)
	ExploreDirectory(ctx context.Context, token string, owner, repo, ref, targetPath string) (*DirectoryDiscoveryResult, error)
	GetBlobContent(ctx context.Context, token, owner, repo, sha string) ([]byte, error)
	GetFileContent(ctx context.Context, token, owner, repo, filePath, ref string) ([]byte, error)
}

type cacheEntry struct {
	data      any
	expiresAt time.Time
}

// HTTPClient implements Client with timeout enforcement, response bounds, and TTL caching.
type HTTPClient struct {
	httpClient       *http.Client
	apiURL           string
	maxResponseBytes int64
	cacheTTL         time.Duration

	mu    sync.RWMutex
	cache map[string]cacheEntry
}

// Option allows customizing HTTPClient.
type Option func(*HTTPClient)

// WithHTTPClient overrides the underlying net/http.Client.
func WithHTTPClient(c *http.Client) Option {
	return func(h *HTTPClient) {
		h.httpClient = c
	}
}

// WithCacheTTL configures the in-memory cache TTL.
func WithCacheTTL(ttl time.Duration) Option {
	return func(h *HTTPClient) {
		h.cacheTTL = ttl
	}
}

// WithMaxResponseBytes configures the maximum readable bytes per response.
func WithMaxResponseBytes(limit int64) Option {
	return func(h *HTTPClient) {
		h.maxResponseBytes = limit
	}
}

// NewHTTPClient creates a production-grade GitHub HTTP client.
func NewHTTPClient(apiURL string, opts ...Option) *HTTPClient {
	h := &HTTPClient{
		httpClient: &http.Client{
			Timeout: 5 * time.Second,
		},
		apiURL:           strings.TrimRight(apiURL, "/"),
		maxResponseBytes: 4 << 20, // 4MB
		cacheTTL:         2 * time.Minute,
		cache:            make(map[string]cacheEntry),
	}
	for _, opt := range opts {
		opt(h)
	}
	return h
}

// ListRepositories lists repositories accessible to the installation token.
func (c *HTTPClient) ListRepositories(ctx context.Context, token string) ([]Repository, error) {
	cacheKey := c.hashKey("repos", token)
	if val, ok := c.getCache(cacheKey); ok {
		return val.([]Repository), nil
	}

	endpoint := c.apiURL + "/installation/repositories?per_page=100"
	var raw struct {
		Repositories []struct {
			ID       int64  `json:"id"`
			Name     string `json:"name"`
			FullName string `json:"full_name"`
			Private  bool   `json:"private"`
			Owner    struct {
				Login string `json:"login"`
			} `json:"owner"`
			DefaultBranch string `json:"default_branch"`
			HTMLURL       string `json:"html_url"`
			Description   string `json:"description"`
			Language      string `json:"language"`
			UpdatedAt     string `json:"updated_at"`
			PushedAt      string `json:"pushed_at"`
		} `json:"repositories"`
	}

	if err := c.doGetJSON(ctx, endpoint, token, &raw); err != nil {
		return nil, err
	}

	repos := make([]Repository, 0, len(raw.Repositories))
	for _, r := range raw.Repositories {
		owner := r.Owner.Login
		if owner == "" {
			owner, _, _ = strings.Cut(r.FullName, "/")
		}
		repos = append(repos, Repository{
			ID:            r.ID,
			Owner:         owner,
			Name:          r.Name,
			FullName:      r.FullName,
			Private:       r.Private,
			DefaultBranch: r.DefaultBranch,
			HTMLURL:       r.HTMLURL,
			Description:   r.Description,
			Language:      r.Language,
			UpdatedAt:     r.UpdatedAt,
			PushedAt:      r.PushedAt,
		})
	}

	parseTime := func(ts string) time.Time {
		if strings.TrimSpace(ts) == "" {
			return time.Time{}
		}
		for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02T15:04:05Z", "2006-01-02 15:04:05"} {
			if t, err := time.Parse(layout, ts); err == nil {
				return t
			}
		}
		return time.Time{}
	}

	sort.Slice(repos, func(i, j int) bool {
		ti := parseTime(repos[i].PushedAt)
		if ti.IsZero() {
			ti = parseTime(repos[i].UpdatedAt)
		}
		tj := parseTime(repos[j].PushedAt)
		if tj.IsZero() {
			tj = parseTime(repos[j].UpdatedAt)
		}
		if !ti.Equal(tj) {
			return ti.After(tj) // Latest first
		}
		return strings.ToLower(repos[i].Name) < strings.ToLower(repos[j].Name)
	})

	c.setCache(cacheKey, repos)
	return repos, nil
}

// ListBranches returns branches for owner/repo using the installation token.
func (c *HTTPClient) ListBranches(ctx context.Context, token string, owner, repo string) ([]Branch, error) {
	cacheKey := c.hashKey("branches", token, owner, repo)
	if val, ok := c.getCache(cacheKey); ok {
		return val.([]Branch), nil
	}

	endpoint := fmt.Sprintf("%s/repos/%s/%s/branches?per_page=100",
		c.apiURL,
		url.PathEscape(strings.TrimSpace(owner)),
		url.PathEscape(strings.TrimSpace(repo)),
	)

	var raw []struct {
		Name      string `json:"name"`
		Protected bool   `json:"protected"`
		Commit    struct {
			SHA string `json:"sha"`
		} `json:"commit"`
	}

	if err := c.doGetJSON(ctx, endpoint, token, &raw); err != nil {
		return nil, err
	}

	branches := make([]Branch, 0, len(raw))
	for _, b := range raw {
		branches = append(branches, Branch{
			Name:      b.Name,
			CommitSHA: b.Commit.SHA,
			Protected: b.Protected,
		})
	}

	c.setCache(cacheKey, branches)
	return branches, nil
}

// ListDirectories returns canonical root directory paths for owner/repo at ref.
func (c *HTTPClient) ListDirectories(ctx context.Context, token string, owner, repo, ref string) ([]string, error) {
	res, err := c.ExploreDirectory(ctx, token, owner, repo, ref, "/")
	if err != nil {
		return nil, err
	}
	return res.Directories, nil
}

// ListDirectoriesWithPresets discovers directory paths and maps each to its detected preset.
func (c *HTTPClient) ListDirectoriesWithPresets(ctx context.Context, token string, owner, repo, ref string) ([]string, map[string]string, error) {
	res, err := c.ExploreDirectory(ctx, token, owner, repo, ref, "/")
	if err != nil {
		return nil, nil, err
	}
	return res.Directories, res.Presets, nil
}

type treeEntry struct {
	Path string `json:"path"`
	Type string `json:"type"`
	SHA  string `json:"sha"`
}

// ExploreDirectory performs on-demand exploration of a directory tree at targetPath.
// It returns framework detection and suggested commands for targetPath alongside its immediate children.
func (c *HTTPClient) ExploreDirectory(ctx context.Context, token string, owner, repo, ref, targetPath string) (*DirectoryDiscoveryResult, error) {
	if strings.TrimSpace(ref) == "" {
		ref = "HEAD"
	}

	normalizedTarget := normalizePath(targetPath)

	cacheKey := c.hashKey("dirs_tree", token, owner, repo, ref)
	var rawTree []treeEntry
	if val, ok := c.getCache(cacheKey); ok {
		if cachedTree, ok := val.([]treeEntry); ok {
			rawTree = cachedTree
		}
	}

	if rawTree == nil {
		endpoint := fmt.Sprintf("%s/repos/%s/%s/git/trees/%s?recursive=1",
			c.apiURL,
			url.PathEscape(strings.TrimSpace(owner)),
			url.PathEscape(strings.TrimSpace(repo)),
			url.PathEscape(strings.TrimSpace(ref)),
		)

		var raw struct {
			Tree []treeEntry `json:"tree"`
		}

		if err := c.doGetJSON(ctx, endpoint, token, &raw); err != nil {
			return nil, err
		}
		rawTree = raw.Tree
		c.setCache(cacheKey, rawTree)
	}

	allDirs := map[string]bool{"/": true}
	dirFiles := make(map[string][]string)
	dirBlobSHAs := make(map[string]map[string]string)
	childDirs := make(map[string]map[string]bool)

	for _, entry := range rawTree {
		clean := strings.Trim(entry.Path, "/")
		if clean == "" || hasHiddenSegment(clean) {
			continue
		}

		if entry.Type == "tree" {
			d := "/" + clean
			allDirs[d] = true
			parent := getParentDir(d)
			allDirs[parent] = true
			if childDirs[parent] == nil {
				childDirs[parent] = make(map[string]bool)
			}
			childDirs[parent][d] = true
		} else if entry.Type == "blob" {
			dir, filename := splitDirFile(clean)
			allDirs[dir] = true
			dirFiles[dir] = append(dirFiles[dir], filename)
			if dirBlobSHAs[dir] == nil {
				dirBlobSHAs[dir] = make(map[string]string)
			}
			dirBlobSHAs[dir][filename] = entry.SHA

			// Ensure ancestors exist in childDirs
			cur := dir
			for cur != "/" && cur != "" {
				p := getParentDir(cur)
				allDirs[p] = true
				if childDirs[p] == nil {
					childDirs[p] = make(map[string]bool)
				}
				childDirs[p][cur] = true
				cur = p
			}
		}
	}

	// Verify targetPath exists
	if normalizedTarget != "/" && !allDirs[normalizedTarget] {
		return nil, ErrNotFound
	}

	fetchPackageJSONForDir := func(d string) func() ([]byte, error) {
		return func() ([]byte, error) {
			sha := ""
			if dirBlobSHAs[d] != nil {
				sha = dirBlobSHAs[d]["package.json"]
			}
			if sha != "" {
				return c.GetBlobContent(ctx, token, owner, repo, sha)
			}
			rel := strings.TrimPrefix(d, "/")
			if rel != "" {
				rel += "/package.json"
			} else {
				rel = "package.json"
			}
			return c.GetFileContent(ctx, token, owner, repo, rel, ref)
		}
	}

	// Detect current directory
	currFramework := DetectFramework(dirFiles[normalizedTarget], fetchPackageJSONForDir(normalizedTarget))
	currChildrenSet := childDirs[normalizedTarget]
	currChildren := make([]string, 0, len(currChildrenSet))
	for ch := range currChildrenSet {
		currChildren = append(currChildren, ch)
	}
	sort.Strings(currChildren)

	currInfo := DirectoryInfo{
		Path:                     normalizedTarget,
		Name:                     getBaseDir(normalizedTarget),
		ParentPath:               getParentDir(normalizedTarget),
		DetectedPreset:           currFramework.Framework,
		SuggestedInstallCommand:  currFramework.SuggestedInstallCommand,
		SuggestedBuildCommand:    currFramework.SuggestedBuildCommand,
		SuggestedRunCommand:      currFramework.SuggestedRunCommand,
		SuggestedOutputDirectory: currFramework.SuggestedOutputDirectory,
		HasChildren:              len(currChildren) > 0,
	}

	// Detect direct children
	childInfos := make([]DirectoryInfo, 0, len(currChildren))
	for _, ch := range currChildren {
		chFramework := DetectFramework(dirFiles[ch], fetchPackageJSONForDir(ch))
		childInfos = append(childInfos, DirectoryInfo{
			Path:                     ch,
			Name:                     getBaseDir(ch),
			ParentPath:               normalizedTarget,
			DetectedPreset:           chFramework.Framework,
			SuggestedInstallCommand:  chFramework.SuggestedInstallCommand,
			SuggestedBuildCommand:    chFramework.SuggestedBuildCommand,
			SuggestedRunCommand:      chFramework.SuggestedRunCommand,
			SuggestedOutputDirectory: chFramework.SuggestedOutputDirectory,
			HasChildren:              len(childDirs[ch]) > 0,
		})
	}

	// Build legacy directories list and presets map for backward compatibility
	allDirsList := make([]string, 0, len(allDirs))
	for d := range allDirs {
		allDirsList = append(allDirsList, d)
	}
	sort.Strings(allDirsList)

	presetsMap := make(map[string]string, len(allDirsList))
	for _, d := range allDirsList {
		// Use fast heuristic without blob calls for whole-tree preset map
		presetsMap[d] = DetectFramework(dirFiles[d], nil).Framework
	}

	return &DirectoryDiscoveryResult{
		CurrentDirectory: currInfo,
		Children:         childInfos,
		Directories:      allDirsList,
		Presets:          presetsMap,
	}, nil
}

// GetBlobContent fetches raw blob content from GitHub by SHA with in-memory caching.
func (c *HTTPClient) GetBlobContent(ctx context.Context, token, owner, repo, sha string) ([]byte, error) {
	if strings.TrimSpace(sha) == "" {
		return nil, ErrInvalidInput
	}
	cacheKey := c.hashKey("blob", token, owner, repo, sha)
	if val, ok := c.getCache(cacheKey); ok {
		return val.([]byte), nil
	}

	endpoint := fmt.Sprintf("%s/repos/%s/%s/git/blobs/%s",
		c.apiURL,
		url.PathEscape(strings.TrimSpace(owner)),
		url.PathEscape(strings.TrimSpace(repo)),
		url.PathEscape(strings.TrimSpace(sha)),
	)

	var raw struct {
		Content  string `json:"content"`
		Encoding string `json:"encoding"`
	}

	if err := c.doGetJSON(ctx, endpoint, token, &raw); err != nil {
		return nil, err
	}

	var data []byte
	var err error
	if raw.Encoding == "base64" {
		cleaned := strings.ReplaceAll(raw.Content, "\n", "")
		data, err = base64.StdEncoding.DecodeString(cleaned)
		if err != nil {
			return nil, fmt.Errorf("%w: base64 decode: %v", ErrUpstream, err)
		}
	} else {
		data = []byte(raw.Content)
	}

	c.setCache(cacheKey, data)
	return data, nil
}

// GetFileContent fetches a repository file content at ref with in-memory caching.
func (c *HTTPClient) GetFileContent(ctx context.Context, token, owner, repo, filePath, ref string) ([]byte, error) {
	cleanPath := strings.Trim(filePath, "/")
	if cleanPath == "" {
		return nil, ErrInvalidInput
	}
	cacheKey := c.hashKey("content", token, owner, repo, ref, cleanPath)
	if val, ok := c.getCache(cacheKey); ok {
		return val.([]byte), nil
	}

	endpoint := fmt.Sprintf("%s/repos/%s/%s/contents/%s?ref=%s",
		c.apiURL,
		url.PathEscape(strings.TrimSpace(owner)),
		url.PathEscape(strings.TrimSpace(repo)),
		cleanPath,
		url.QueryEscape(strings.TrimSpace(ref)),
	)

	var raw struct {
		Content  string `json:"content"`
		Encoding string `json:"encoding"`
	}

	if err := c.doGetJSON(ctx, endpoint, token, &raw); err != nil {
		return nil, err
	}

	var data []byte
	var err error
	if raw.Encoding == "base64" {
		cleaned := strings.ReplaceAll(raw.Content, "\n", "")
		data, err = base64.StdEncoding.DecodeString(cleaned)
		if err != nil {
			return nil, fmt.Errorf("%w: base64 decode: %v", ErrUpstream, err)
		}
	} else {
		data = []byte(raw.Content)
	}

	c.setCache(cacheKey, data)
	return data, nil
}

// DetectPresetFromFiles inspects manifest filenames present directly inside a directory
// and returns "nextjs", "vite", "golang", or "other".
func DetectPresetFromFiles(files []string) string {
	res := DetectFramework(files, nil)
	return res.Framework
}

type packageManager string

const (
	pmNPM  packageManager = "npm"
	pmPNPM packageManager = "pnpm"
	pmYarn packageManager = "yarn"
	pmBun  packageManager = "bun"
)

func detectPackageManager(fileSet map[string]bool) packageManager {
	if fileSet["pnpm-lock.yaml"] {
		return pmPNPM
	}
	if fileSet["yarn.lock"] {
		return pmYarn
	}
	if fileSet["bun.lockb"] || fileSet["bun.lock"] {
		return pmBun
	}
	return pmNPM
}

func makeNextJSResult(pm packageManager) FrameworkDetectionResult {
	switch pm {
	case pmPNPM:
		return FrameworkDetectionResult{
			Framework:                "nextjs",
			SuggestedInstallCommand:  "pnpm install",
			SuggestedBuildCommand:    "pnpm run build",
			SuggestedRunCommand:      "pnpm start",
			SuggestedOutputDirectory: ".next",
		}
	case pmYarn:
		return FrameworkDetectionResult{
			Framework:                "nextjs",
			SuggestedInstallCommand:  "yarn install",
			SuggestedBuildCommand:    "yarn build",
			SuggestedRunCommand:      "yarn start",
			SuggestedOutputDirectory: ".next",
		}
	case pmBun:
		return FrameworkDetectionResult{
			Framework:                "nextjs",
			SuggestedInstallCommand:  "bun install",
			SuggestedBuildCommand:    "bun run build",
			SuggestedRunCommand:      "bun start",
			SuggestedOutputDirectory: ".next",
		}
	default:
		return FrameworkDetectionResult{
			Framework:                "nextjs",
			SuggestedInstallCommand:  "npm install",
			SuggestedBuildCommand:    "npm run build",
			SuggestedRunCommand:      "npm start",
			SuggestedOutputDirectory: ".next",
		}
	}
}

func makeViteResult(pm packageManager) FrameworkDetectionResult {
	switch pm {
	case pmPNPM:
		return FrameworkDetectionResult{
			Framework:                "vite",
			SuggestedInstallCommand:  "pnpm install",
			SuggestedBuildCommand:    "pnpm run build",
			SuggestedRunCommand:      "pnpm run preview",
			SuggestedOutputDirectory: "dist",
		}
	case pmYarn:
		return FrameworkDetectionResult{
			Framework:                "vite",
			SuggestedInstallCommand:  "yarn install",
			SuggestedBuildCommand:    "yarn build",
			SuggestedRunCommand:      "yarn preview",
			SuggestedOutputDirectory: "dist",
		}
	case pmBun:
		return FrameworkDetectionResult{
			Framework:                "vite",
			SuggestedInstallCommand:  "bun install",
			SuggestedBuildCommand:    "bun run build",
			SuggestedRunCommand:      "bun run preview",
			SuggestedOutputDirectory: "dist",
		}
	default:
		return FrameworkDetectionResult{
			Framework:                "vite",
			SuggestedInstallCommand:  "npm install",
			SuggestedBuildCommand:    "npm run build",
			SuggestedRunCommand:      "npm run preview",
			SuggestedOutputDirectory: "dist",
		}
	}
}

type packageJSON struct {
	Dependencies    map[string]string `json:"dependencies"`
	DevDependencies map[string]string `json:"devDependencies"`
	Scripts         map[string]string `json:"scripts"`
}

// DetectFramework inspects manifest filenames and optionally package.json content to robustly
// identify Vite, Next.js, Golang, or Other.
func DetectFramework(files []string, fetchPackageJSON func() ([]byte, error)) FrameworkDetectionResult {
	if len(files) == 0 {
		return FrameworkDetectionResult{
			Framework:                "other",
			SuggestedInstallCommand:  "",
			SuggestedBuildCommand:    "",
			SuggestedRunCommand:      "",
			SuggestedOutputDirectory: "",
		}
	}

	fileSet := make(map[string]bool, len(files))
	for _, f := range files {
		fileSet[strings.ToLower(f)] = true
	}

	// 1. Golang check: go.mod, go.sum, main.go, or any .go file
	hasGoFile := false
	for f := range fileSet {
		if strings.HasSuffix(f, ".go") {
			hasGoFile = true
			break
		}
	}
	if fileSet["go.mod"] || fileSet["go.sum"] || hasGoFile {
		return FrameworkDetectionResult{
			Framework:                "golang",
			SuggestedInstallCommand:  "go mod download",
			SuggestedBuildCommand:    "go build -o out/app ./...",
			SuggestedRunCommand:      "./out/app",
			SuggestedOutputDirectory: "out",
		}
	}

	pm := detectPackageManager(fileSet)

	// 2. Next.js check by config files
	if fileSet["next.config.js"] || fileSet["next.config.mjs"] || fileSet["next.config.ts"] {
		return makeNextJSResult(pm)
	}

	// 3. Vite check by config files
	if fileSet["vite.config.js"] || fileSet["vite.config.ts"] || fileSet["vite.config.mjs"] || fileSet["vite.config.cjs"] {
		return makeViteResult(pm)
	}

	// 4. Ambiguous check: If package.json is present, inspect dependencies and scripts
	if fileSet["package.json"] && fetchPackageJSON != nil {
		if data, err := fetchPackageJSON(); err == nil && len(data) > 0 {
			var pkg packageJSON
			if err := json.Unmarshal(data, &pkg); err == nil {
				isNext := false
				isVite := false

				if _, ok := pkg.Dependencies["next"]; ok {
					isNext = true
				} else if _, ok := pkg.DevDependencies["next"]; ok {
					isNext = true
				}

				if _, ok := pkg.Dependencies["vite"]; ok {
					isVite = true
				} else if _, ok := pkg.DevDependencies["vite"]; ok {
					isVite = true
				}

				if !isNext && !isVite {
					for _, cmd := range pkg.Scripts {
						cmdLower := strings.ToLower(cmd)
						if strings.Contains(cmdLower, "next ") || strings.HasPrefix(cmdLower, "next") {
							isNext = true
							break
						}
						if strings.Contains(cmdLower, "vite ") || strings.HasPrefix(cmdLower, "vite") {
							isVite = true
							break
						}
					}
				}

				if isNext {
					return makeNextJSResult(pm)
				}
				if isVite {
					return makeViteResult(pm)
				}
			}
		}
	}

	// 5. Fallback heuristics for Vite (index.html + package.json)
	if fileSet["index.html"] && fileSet["package.json"] {
		return makeViteResult(pm)
	}

	// 6. Otherwise: "other"
	return FrameworkDetectionResult{
		Framework:                "other",
		SuggestedInstallCommand:  "",
		SuggestedBuildCommand:    "",
		SuggestedRunCommand:      "",
		SuggestedOutputDirectory: "",
	}
}

func (c *HTTPClient) doGetJSON(ctx context.Context, endpoint, token string, dst any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return fmt.Errorf("%w: new request: %v", ErrUpstream, err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUpstream, err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		// success
	case http.StatusUnauthorized:
		return ErrUnauthorized
	case http.StatusNotFound:
		return ErrNotFound
	case http.StatusForbidden, http.StatusTooManyRequests:
		return ErrRateLimited
	default:
		return fmt.Errorf("%w: status %d", ErrUpstream, resp.StatusCode)
	}

	limit := c.maxResponseBytes
	if limit <= 0 {
		limit = 4 << 20
	}

	if err := json.NewDecoder(io.LimitReader(resp.Body, limit)).Decode(dst); err != nil {
		return fmt.Errorf("%w: decode: %v", ErrUpstream, err)
	}
	return nil
}

func hasHiddenSegment(p string) bool {
	for _, seg := range strings.Split(p, "/") {
		if strings.HasPrefix(seg, ".") || seg == "node_modules" || seg == "vendor" {
			return true
		}
	}
	return false
}

func normalizePath(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" || trimmed == "." || trimmed == "/" || trimmed == "./" {
		return "/"
	}
	cleaned := path.Clean("/" + strings.TrimLeft(trimmed, "./"))
	if !strings.HasPrefix(cleaned, "/") {
		cleaned = "/" + cleaned
	}
	return cleaned
}

func getParentDir(d string) string {
	if d == "/" || d == "" {
		return "/"
	}
	lastSlash := strings.LastIndex(d, "/")
	if lastSlash <= 0 {
		return "/"
	}
	return d[:lastSlash]
}

func getBaseDir(d string) string {
	if d == "/" || d == "" {
		return "/"
	}
	lastSlash := strings.LastIndex(d, "/")
	if lastSlash < 0 {
		return d
	}
	return d[lastSlash+1:]
}

func splitDirFile(clean string) (string, string) {
	lastSlash := strings.LastIndex(clean, "/")
	if lastSlash < 0 {
		return "/", clean
	}
	return "/" + clean[:lastSlash], clean[lastSlash+1:]
}

func (c *HTTPClient) hashKey(prefix, token string, parts ...string) string {
	h := sha256.New()
	tokenHash := sha256.Sum256([]byte(token))
	h.Write([]byte(prefix))
	h.Write(tokenHash[:])
	for _, p := range parts {
		h.Write([]byte("/" + p))
	}
	return hex.EncodeToString(h.Sum(nil))
}

func (c *HTTPClient) getCache(key string) (any, bool) {
	if c.cacheTTL <= 0 {
		return nil, false
	}
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, ok := c.cache[key]
	if !ok || time.Now().After(entry.expiresAt) {
		return nil, false
	}
	return entry.data, true
}

func (c *HTTPClient) setCache(key string, data any) {
	if c.cacheTTL <= 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	if len(c.cache) > 2000 {
		now := time.Now()
		for k, v := range c.cache {
			if now.After(v.expiresAt) {
				delete(c.cache, k)
			}
		}
	}

	c.cache[key] = cacheEntry{
		data:      data,
		expiresAt: time.Now().Add(c.cacheTTL),
	}
}

// InvalidateCache clears all cached repository lists, branch lists, and directory trees.
func (c *HTTPClient) InvalidateCache() {
	if c == nil {
		return
	}
	c.mu.Lock()
	clear(c.cache)
	c.mu.Unlock()
}
