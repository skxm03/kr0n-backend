package oauth

import (
	"context"
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

var (
	// ErrGitHubAppNotConfigured indicates GitHub App credentials are not configured.
	ErrGitHubAppNotConfigured = errors.New("github app is not configured")
	// ErrInvalidInstallationState indicates the installation state token is invalid or expired.
	ErrInvalidInstallationState = errors.New("invalid or expired github installation state")
	// ErrGitHubAppAPI indicates a failure communicating with the GitHub App API.
	ErrGitHubAppAPI = errors.New("github app api request failed")
)

// GitHubAppInstallation represents metadata fetched from GitHub for an App installation.
type GitHubAppInstallation struct {
	InstallationID      int64
	AccountLogin        string
	AccountType         string
	RepositorySelection string
	Status              string
}

// GitHubRepository represents a source repository accessible to a GitHub Installation.
type GitHubRepository struct {
	ID            int64  `json:"id"`
	Name          string `json:"name"`
	FullName      string `json:"full_name"`
	Private       bool   `json:"private"`
	DefaultBranch string `json:"default_branch"`
	HTMLURL       string `json:"html_url"`
}

// GitHubBranch represents a branch in a GitHub repository.
type GitHubBranch struct {
	Name      string `json:"name"`
	CommitSHA string `json:"commit_sha"`
	Protected bool   `json:"protected"`
}

// GitHubAppConfig configures the GitHub App provider.
type GitHubAppConfig struct {
	AppID         string
	AppSlug       string
	PrivateKeyPEM string
	StateSecret   string
	APIURL        string
	HTTPClient    *http.Client
}

type cachedInstToken struct {
	token     string
	expiresAt time.Time
}

// GitHubAppProvider implements GitHub App authentication, state signing, and repository exploration.
type GitHubAppProvider struct {
	cfg        GitHubAppConfig
	privateKey *rsa.PrivateKey
	mu         sync.Mutex
	tokens     map[int64]cachedInstToken
}

// NewGitHubAppProvider creates a GitHubAppProvider.
func NewGitHubAppProvider(cfg GitHubAppConfig) (*GitHubAppProvider, error) {
	if cfg.APIURL == "" {
		cfg.APIURL = "https://api.github.com"
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 10 * time.Second}
	}
	var priv *rsa.PrivateKey
	if raw := strings.TrimSpace(cfg.PrivateKeyPEM); raw != "" {
		parsed, err := parseRSAPrivateKey(raw)
		if err != nil {
			return nil, fmt.Errorf("parse github app private key: %w", err)
		}
		priv = parsed
	}
	return &GitHubAppProvider{
		cfg:        cfg,
		privateKey: priv,
		tokens:     make(map[int64]cachedInstToken),
	}, nil
}

func parseRSAPrivateKey(pemStr string) (*rsa.PrivateKey, error) {
	normalized := strings.ReplaceAll(pemStr, `\n`, "\n")
	block, _ := pem.Decode([]byte(normalized))
	if block == nil {
		return nil, errors.New("invalid PEM block")
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	pkcs8Key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	rsaKey, ok := pkcs8Key.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("private key is not RSA")
	}
	return rsaKey, nil
}

// Configured reports whether the GitHub App is configured with AppID, AppSlug, and PrivateKey.
func (p *GitHubAppProvider) Configured() bool {
	return p != nil &&
		strings.TrimSpace(p.cfg.AppID) != "" &&
		strings.TrimSpace(p.cfg.AppSlug) != "" &&
		p.privateKey != nil
}

func (p *GitHubAppProvider) stateKey() []byte {
	if s := strings.TrimSpace(p.cfg.StateSecret); s != "" {
		return []byte(s)
	}
	if p.privateKey != nil {
		return p.privateKey.N.Bytes()
	}
	return nil
}

// StartInstallation generates a signed, 15-minute state token bound to orgID and userID and returns the GitHub App installation URL.
func (p *GitHubAppProvider) StartInstallation(orgID, userID uuid.UUID) (installURL, state string, err error) {
	if !p.Configured() {
		return "", "", ErrGitHubAppNotConfigured
	}
	if orgID == uuid.Nil || userID == uuid.Nil {
		return "", "", ErrInvalidInstallationState
	}
	nonce, err := randomBase64URL(12)
	if err != nil {
		return "", "", err
	}
	exp := time.Now().UTC().Add(15 * time.Minute).Unix()
	payload := fmt.Sprintf("%s:%s:%d:%s", orgID.String(), userID.String(), exp, nonce)
	payloadB64 := base64.RawURLEncoding.EncodeToString([]byte(payload))

	mac := hmac.New(sha256.New, p.stateKey())
	mac.Write([]byte(payloadB64))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	state = payloadB64 + "." + sig

	u := fmt.Sprintf("https://github.com/apps/%s/installations/new?state=%s", url.PathEscape(strings.TrimSpace(p.cfg.AppSlug)), url.QueryEscape(state))
	return u, state, nil
}

// VerifyState verifies the HMAC signature, expiry, orgID, and userID of a GitHub installation state token.
func (p *GitHubAppProvider) VerifyState(state string, expectedOrgID, expectedUserID uuid.UUID) error {
	if !p.Configured() {
		return ErrGitHubAppNotConfigured
	}
	payloadB64, sigB64, ok := strings.Cut(strings.TrimSpace(state), ".")
	if !ok || payloadB64 == "" || sigB64 == "" {
		return ErrInvalidInstallationState
	}

	mac := hmac.New(sha256.New, p.stateKey())
	mac.Write([]byte(payloadB64))
	wantSig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(sigB64), []byte(wantSig)) {
		return ErrInvalidInstallationState
	}

	raw, err := base64.RawURLEncoding.DecodeString(payloadB64)
	if err != nil {
		return ErrInvalidInstallationState
	}
	parts := strings.Split(string(raw), ":")
	if len(parts) != 4 {
		return ErrInvalidInstallationState
	}
	if parts[0] != expectedOrgID.String() || parts[1] != expectedUserID.String() {
		return ErrInvalidInstallationState
	}
	exp, err := strconv.ParseInt(parts[2], 10, 64)
	if err != nil || time.Now().UTC().Unix() > exp {
		return ErrInvalidInstallationState
	}
	return nil
}

func (p *GitHubAppProvider) signAppJWT() (string, error) {
	now := time.Now().UTC()
	headerJSON := `{"alg":"RS256","typ":"JWT"}`
	claimsJSON, err := json.Marshal(map[string]any{
		"iat": now.Add(-60 * time.Second).Unix(),
		"exp": now.Add(9 * time.Minute).Unix(),
		"iss": strings.TrimSpace(p.cfg.AppID),
	})
	if err != nil {
		return "", err
	}
	signingInput := base64.RawURLEncoding.EncodeToString([]byte(headerJSON)) + "." + base64.RawURLEncoding.EncodeToString(claimsJSON)
	digest := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, p.privateKey, crypto.SHA256, digest[:])
	if err != nil {
		return "", err
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

func (p *GitHubAppProvider) installationToken(ctx context.Context, installationID int64) (string, error) {
	now := time.Now().UTC()
	p.mu.Lock()
	if cached, ok := p.tokens[installationID]; ok && now.Add(2*time.Minute).Before(cached.expiresAt) {
		p.mu.Unlock()
		return cached.token, nil
	}
	p.mu.Unlock()

	appJWT, err := p.signAppJWT()
	if err != nil {
		return "", fmt.Errorf("%w: sign app jwt: %v", ErrGitHubAppAPI, err)
	}

	endpoint := fmt.Sprintf("%s/app/installations/%d/access_tokens", strings.TrimRight(p.cfg.APIURL, "/"), installationID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, nil)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrGitHubAppAPI, err)
	}
	req.Header.Set("Authorization", "Bearer "+appJWT)
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := p.cfg.HTTPClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrGitHubAppAPI, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("%w: mint installation token status %d", ErrGitHubAppAPI, resp.StatusCode)
	}

	var tokResp struct {
		Token     string    `json:"token"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&tokResp); err != nil || strings.TrimSpace(tokResp.Token) == "" {
		return "", ErrGitHubAppAPI
	}
	if tokResp.ExpiresAt.IsZero() {
		tokResp.ExpiresAt = now.Add(55 * time.Minute)
	}

	p.mu.Lock()
	p.tokens[installationID] = cachedInstToken{token: tokResp.Token, expiresAt: tokResp.ExpiresAt}
	p.mu.Unlock()

	return tokResp.Token, nil
}

// GetInstallation fetches installation metadata from GitHub using the App JWT.
func (p *GitHubAppProvider) GetInstallation(ctx context.Context, installationID int64) (*GitHubAppInstallation, error) {
	if !p.Configured() {
		return nil, ErrGitHubAppNotConfigured
	}
	if installationID <= 0 {
		return nil, ErrGitHubAppAPI
	}
	appJWT, err := p.signAppJWT()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrGitHubAppAPI, err)
	}
	endpoint := fmt.Sprintf("%s/app/installations/%d", strings.TrimRight(p.cfg.APIURL, "/"), installationID)
	var raw struct {
		ID                  int64      `json:"id"`
		RepositorySelection string     `json:"repository_selection"`
		SuspendedAt         *time.Time `json:"suspended_at"`
		Account             struct {
			Login string `json:"login"`
			Type  string `json:"type"`
		} `json:"account"`
	}
	if err := p.doGetJSON(ctx, endpoint, appJWT, &raw); err != nil {
		return nil, err
	}
	if raw.ID == 0 || strings.TrimSpace(raw.Account.Login) == "" {
		return nil, ErrGitHubAppAPI
	}
	status := "active"
	if raw.SuspendedAt != nil {
		status = "suspended"
	}
	sel := raw.RepositorySelection
	if sel != "selected" {
		sel = "all"
	}
	acctType := raw.Account.Type
	if acctType == "" {
		acctType = "Organization"
	}
	return &GitHubAppInstallation{
		InstallationID:      raw.ID,
		AccountLogin:        raw.Account.Login,
		AccountType:         acctType,
		RepositorySelection: sel,
		Status:              status,
	}, nil
}

// ListRepositories returns repositories accessible to installationID.
func (p *GitHubAppProvider) ListRepositories(ctx context.Context, installationID int64) ([]GitHubRepository, error) {
	if !p.Configured() {
		return nil, ErrGitHubAppNotConfigured
	}
	tok, err := p.installationToken(ctx, installationID)
	if err != nil {
		return nil, err
	}
	endpoint := strings.TrimRight(p.cfg.APIURL, "/") + "/installation/repositories?per_page=100"
	var raw struct {
		Repositories []GitHubRepository `json:"repositories"`
	}
	if err := p.doGetJSON(ctx, endpoint, tok, &raw); err != nil {
		return nil, err
	}
	return raw.Repositories, nil
}

// ListBranches returns branches for owner/repo using installationID's token.
func (p *GitHubAppProvider) ListBranches(ctx context.Context, installationID int64, owner, repo string) ([]GitHubBranch, error) {
	if !p.Configured() {
		return nil, ErrGitHubAppNotConfigured
	}
	tok, err := p.installationToken(ctx, installationID)
	if err != nil {
		return nil, err
	}
	endpoint := fmt.Sprintf("%s/repos/%s/%s/branches?per_page=100",
		strings.TrimRight(p.cfg.APIURL, "/"),
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
	if err := p.doGetJSON(ctx, endpoint, tok, &raw); err != nil {
		return nil, err
	}
	out := make([]GitHubBranch, 0, len(raw))
	for _, b := range raw {
		out = append(out, GitHubBranch{
			Name:      b.Name,
			CommitSHA: b.Commit.SHA,
			Protected: b.Protected,
		})
	}
	return out, nil
}

// ListDirectories returns canonical Root Directory paths ("/", "/apps/api", etc.) for owner/repo at ref.
func (p *GitHubAppProvider) ListDirectories(ctx context.Context, installationID int64, owner, repo, ref string) ([]string, error) {
	if !p.Configured() {
		return nil, ErrGitHubAppNotConfigured
	}
	if strings.TrimSpace(ref) == "" {
		ref = "HEAD"
	}
	tok, err := p.installationToken(ctx, installationID)
	if err != nil {
		return nil, err
	}
	endpoint := fmt.Sprintf("%s/repos/%s/%s/git/trees/%s?recursive=1",
		strings.TrimRight(p.cfg.APIURL, "/"),
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
	if err := p.doGetJSON(ctx, endpoint, tok, &raw); err != nil {
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
	return dirs, nil
}

func hasHiddenSegment(path string) bool {
	for _, seg := range strings.Split(path, "/") {
		if strings.HasPrefix(seg, ".") || seg == "node_modules" || seg == "vendor" {
			return true
		}
	}
	return false
}

func (p *GitHubAppProvider) doGetJSON(ctx context.Context, endpoint, bearerToken string, dst any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrGitHubAppAPI, err)
	}
	req.Header.Set("Authorization", "Bearer "+bearerToken)
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := p.cfg.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrGitHubAppAPI, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%w: status %d", ErrGitHubAppAPI, resp.StatusCode)
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(dst); err != nil {
		return fmt.Errorf("%w: decode: %v", ErrGitHubAppAPI, err)
	}
	return nil
}
