package oauth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/skxm03/kr0n-backend/control-plane/internal/auth/user"
)

var (
	// ErrNotConfigured indicates GitHub OAuth credentials are not configured.
	ErrNotConfigured = errors.New("github oauth is not configured")
	// ErrExchangeFailed indicates the OAuth authorization code exchange or profile fetch failed.
	ErrExchangeFailed = errors.New("github oauth code exchange failed")
)

// GitHubConfig configures the GitHub OAuth 2.0 + PKCE client.
type GitHubConfig struct {
	ClientID     string
	ClientSecret string
	RedirectURL  string
	AuthorizeURL string
	TokenURL     string
	APIURL       string
	HTTPClient   *http.Client
}

// GitHubProvider implements GitHub OAuth 2.0 with PKCE (S256).
type GitHubProvider struct {
	cfg GitHubConfig
}

// NewGitHubProvider creates a GitHubProvider with sensible production defaults.
func NewGitHubProvider(cfg GitHubConfig) *GitHubProvider {
	if cfg.AuthorizeURL == "" {
		cfg.AuthorizeURL = "https://github.com/login/oauth/authorize"
	}
	if cfg.TokenURL == "" {
		cfg.TokenURL = "https://github.com/login/oauth/access_token"
	}
	if cfg.APIURL == "" {
		cfg.APIURL = "https://api.github.com"
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 10 * time.Second}
	}
	return &GitHubProvider{cfg: cfg}
}

// Configured reports whether client_id, client_secret, and redirect_url are all non-empty.
func (p *GitHubProvider) Configured() bool {
	return p != nil &&
		strings.TrimSpace(p.cfg.ClientID) != "" &&
		strings.TrimSpace(p.cfg.ClientSecret) != "" &&
		strings.TrimSpace(p.cfg.RedirectURL) != ""
}

// Start generates a 32-byte state, a 32-byte PKCE code_verifier, and the GitHub authorize URL.
func (p *GitHubProvider) Start() (authorizeURL, state, codeVerifier string, err error) {
	if !p.Configured() {
		return "", "", "", ErrNotConfigured
	}
	state, err = randomBase64URL(32)
	if err != nil {
		return "", "", "", err
	}
	codeVerifier, err = randomBase64URL(32)
	if err != nil {
		return "", "", "", err
	}
	sum := sha256.Sum256([]byte(codeVerifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])

	u, err := url.Parse(p.cfg.AuthorizeURL)
	if err != nil {
		return "", "", "", fmt.Errorf("parse authorize url: %w", err)
	}
	q := u.Query()
	q.Set("client_id", p.cfg.ClientID)
	q.Set("redirect_uri", p.cfg.RedirectURL)
	q.Set("response_type", "code")
	q.Set("scope", "read:user user:email")
	q.Set("state", state)
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")
	u.RawQuery = q.Encode()

	return u.String(), state, codeVerifier, nil
}

// ExchangeAndFetchProfile exchanges an OAuth code + PKCE verifier for a GitHub access token
// and fetches the user's profile and verified primary email.
func (p *GitHubProvider) ExchangeAndFetchProfile(ctx context.Context, code, codeVerifier string) (*user.OAuthProfile, error) {
	if !p.Configured() {
		return nil, ErrNotConfigured
	}
	if strings.TrimSpace(code) == "" || strings.TrimSpace(codeVerifier) == "" {
		return nil, ErrExchangeFailed
	}

	accessToken, err := p.exchangeToken(ctx, code, codeVerifier)
	if err != nil {
		return nil, err
	}

	var ghUser struct {
		ID        int64  `json:"id"`
		Login     string `json:"login"`
		Name      string `json:"name"`
		AvatarURL string `json:"avatar_url"`
	}
	if err := p.getJSON(ctx, strings.TrimRight(p.cfg.APIURL, "/")+"/user", accessToken, &ghUser); err != nil {
		return nil, err
	}
	if ghUser.ID == 0 {
		return nil, ErrExchangeFailed
	}

	var ghEmails []struct {
		Email    string `json:"email"`
		Primary  bool   `json:"primary"`
		Verified bool   `json:"verified"`
	}
	if err := p.getJSON(ctx, strings.TrimRight(p.cfg.APIURL, "/")+"/user/emails", accessToken, &ghEmails); err != nil {
		return nil, err
	}

	var verifiedEmail string
	for _, e := range ghEmails {
		if e.Verified && e.Primary && strings.TrimSpace(e.Email) != "" {
			verifiedEmail = strings.TrimSpace(e.Email)
			break
		}
		if e.Verified && verifiedEmail == "" && strings.TrimSpace(e.Email) != "" {
			verifiedEmail = strings.TrimSpace(e.Email)
		}
	}
	if verifiedEmail == "" {
		return nil, user.ErrOAuthEmailNotVerified
	}

	displayName := strings.TrimSpace(ghUser.Name)
	if displayName == "" {
		displayName = strings.TrimSpace(ghUser.Login)
	}
	var avatar *string
	if a := strings.TrimSpace(ghUser.AvatarURL); a != "" {
		avatar = &a
	}

	return &user.OAuthProfile{
		Provider:       "github",
		ProviderUserID: strconv.FormatInt(ghUser.ID, 10),
		Email:          verifiedEmail,
		EmailVerified:  true,
		DisplayName:    displayName,
		AvatarURL:      avatar,
	}, nil
}

func (p *GitHubProvider) exchangeToken(ctx context.Context, code, codeVerifier string) (string, error) {
	form := url.Values{
		"client_id":     {p.cfg.ClientID},
		"client_secret": {p.cfg.ClientSecret},
		"code":          {code},
		"redirect_uri":  {p.cfg.RedirectURL},
		"code_verifier": {codeVerifier},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.cfg.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrExchangeFailed, err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := p.cfg.HTTPClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrExchangeFailed, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", ErrExchangeFailed
	}

	var tokResp struct {
		AccessToken string `json:"access_token"`
		Error       string `json:"error"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&tokResp); err != nil {
		return "", ErrExchangeFailed
	}
	if tokResp.Error != "" || strings.TrimSpace(tokResp.AccessToken) == "" {
		return "", ErrExchangeFailed
	}
	return tokResp.AccessToken, nil
}

func (p *GitHubProvider) getJSON(ctx context.Context, endpoint, accessToken string, dst any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrExchangeFailed, err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := p.cfg.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrExchangeFailed, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return ErrExchangeFailed
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(dst); err != nil {
		return ErrExchangeFailed
	}
	return nil
}

func randomBase64URL(numBytes int) (string, error) {
	b := make([]byte, numBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate random bytes: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
