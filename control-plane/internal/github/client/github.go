package client

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
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

// Client defines the contract for communicating with GitHub REST endpoints.
type Client interface {
	ListRepositories(ctx context.Context, token string) ([]Repository, error)
	ListBranches(ctx context.Context, token string, owner, repo string) ([]Branch, error)
	ListDirectories(ctx context.Context, token string, owner, repo, ref string) ([]string, error)
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

// ListDirectories returns canonical root directory paths ("/", "/apps/api") for owner/repo at ref.
func (c *HTTPClient) ListDirectories(ctx context.Context, token string, owner, repo, ref string) ([]string, error) {
	if strings.TrimSpace(ref) == "" {
		ref = "HEAD"
	}
	cacheKey := c.hashKey("dirs", token, owner, repo, ref)
	if val, ok := c.getCache(cacheKey); ok {
		return val.([]string), nil
	}

	endpoint := fmt.Sprintf("%s/repos/%s/%s/git/trees/%s?recursive=1",
		c.apiURL,
		url.PathEscape(strings.TrimSpace(owner)),
		url.PathEscape(strings.TrimSpace(repo)),
		url.PathEscape(strings.TrimSpace(ref)),
	)

	var raw struct {
		Tree []struct {
			Path string `json:"path"`
			Type string `json:"type"`
		} `json:"tree"`
	}

	if err := c.doGetJSON(ctx, endpoint, token, &raw); err != nil {
		return nil, err
	}

	dirs := []string{"/"}
	seen := map[string]bool{"/": true}
	for _, entry := range raw.Tree {
		if entry.Type != "tree" {
			continue
		}
		clean := strings.Trim(entry.Path, "/")
		if clean == "" || hasHiddenSegment(clean) {
			continue
		}
		dir := "/" + clean
		if !seen[dir] {
			seen[dir] = true
			dirs = append(dirs, dir)
		}
	}
	sort.Strings(dirs[1:])

	c.setCache(cacheKey, dirs)
	return dirs, nil
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

func hasHiddenSegment(path string) bool {
	for _, seg := range strings.Split(path, "/") {
		if strings.HasPrefix(seg, ".") || seg == "node_modules" || seg == "vendor" {
			return true
		}
	}
	return false
}

func (c *HTTPClient) hashKey(prefix, token string, parts ...string) string {
	h := sha256.New()
	// Salt/hash token so memory dumps do not reveal bearer tokens in plaintext cache keys
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

	// Simple periodic prune if cache grows large
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
