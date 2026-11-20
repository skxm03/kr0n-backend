package oauth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/skxm03/kr0n-backend/control-plane/internal/auth/repository"
)

var (
	// ErrGoogleNotConfigured indicates Google OAuth credentials are not configured.
	ErrGoogleNotConfigured = errors.New("google oauth is not configured")
	// ErrGoogleExchangeFailed indicates the OAuth authorization code exchange or profile fetch failed.
	ErrGoogleExchangeFailed = errors.New("google oauth code exchange failed")
)

// GoogleConfig configures the Google OAuth 2.0 + PKCE client.
type GoogleConfig struct {
	ClientID     string
	ClientSecret string
	RedirectURL  string
	AuthorizeURL string
	TokenURL     string
	UserInfoURL  string
	HTTPClient   *http.Client
}

// GoogleProvider implements Google OAuth 2.0 with PKCE (S256).
type GoogleProvider struct {
	cfg GoogleConfig
}

// NewGoogleProvider creates a GoogleProvider with standard Google OIDC endpoints.
func NewGoogleProvider(cfg GoogleConfig) *GoogleProvider {
	if cfg.AuthorizeURL == "" {
		cfg.AuthorizeURL = "https://accounts.google.com/o/oauth2/v2/auth"
	}
	if cfg.TokenURL == "" {
		cfg.TokenURL = "https://oauth2.googleapis.com/token"
	}
	if cfg.UserInfoURL == "" {
		cfg.UserInfoURL = "https://openidconnect.googleapis.com/v1/userinfo"
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 10 * time.Second}
	}
	return &GoogleProvider{cfg: cfg}
}

// Configured reports whether client_id, client_secret, and redirect_url are configured.
func (p *GoogleProvider) Configured() bool {
	return p != nil &&
		strings.TrimSpace(p.cfg.ClientID) != "" &&
		strings.TrimSpace(p.cfg.ClientSecret) != "" &&
		strings.TrimSpace(p.cfg.RedirectURL) != ""
}

// Start generates state, PKCE code_verifier, and the Google authorize URL.
func (p *GoogleProvider) Start() (authorizeURL, state, codeVerifier string, err error) {
	if !p.Configured() {
		return "", "", "", ErrGoogleNotConfigured
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
	q.Set("scope", "openid email profile")
	q.Set("state", state)
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")
	q.Set("access_type", "offline")
	q.Set("prompt", "select_account")
	u.RawQuery = q.Encode()

	return u.String(), state, codeVerifier, nil
}

// ExchangeAndFetchProfile exchanges an OAuth code + PKCE verifier for a Google access token
// and fetches the user's verified profile information.
func (p *GoogleProvider) ExchangeAndFetchProfile(ctx context.Context, code, codeVerifier string) (*repository.OAuthProfile, error) {
	if !p.Configured() {
		return nil, ErrGoogleNotConfigured
	}
	if strings.TrimSpace(code) == "" || strings.TrimSpace(codeVerifier) == "" {
		return nil, ErrGoogleExchangeFailed
	}

	accessToken, err := p.exchangeToken(ctx, code, codeVerifier)
	if err != nil {
		return nil, err
	}

	var googleUser struct {
		Sub           string `json:"sub"`
		Name          string `json:"name"`
		GivenName     string `json:"given_name"`
		FamilyName    string `json:"family_name"`
		Picture       string `json:"picture"`
		Email         string `json:"email"`
		EmailVerified any    `json:"email_verified"`
	}
	if err := p.getJSON(ctx, p.cfg.UserInfoURL, accessToken, &googleUser); err != nil {
		return nil, err
	}
	if strings.TrimSpace(googleUser.Sub) == "" {
		return nil, ErrGoogleExchangeFailed
	}

	var isEmailVerified bool
	switch v := googleUser.EmailVerified.(type) {
	case bool:
		isEmailVerified = v
	case string:
		isEmailVerified = strings.EqualFold(v, "true")
	}
	if !isEmailVerified || strings.TrimSpace(googleUser.Email) == "" {
		return nil, repository.ErrOAuthEmailNotVerified
	}

	displayName := strings.TrimSpace(googleUser.Name)
	if displayName == "" {
		displayName = strings.TrimSpace(googleUser.GivenName + " " + googleUser.FamilyName)
	}
	if displayName == "" {
		displayName = strings.Split(googleUser.Email, "@")[0]
	}
	var avatar *string
	if a := strings.TrimSpace(googleUser.Picture); a != "" {
		avatar = &a
	}

	return &repository.OAuthProfile{
		Provider:       "google",
		ProviderUserID: strings.TrimSpace(googleUser.Sub),
		Email:          strings.TrimSpace(googleUser.Email),
		EmailVerified:  true,
		DisplayName:    displayName,
		AvatarURL:      avatar,
	}, nil
}

func (p *GoogleProvider) exchangeToken(ctx context.Context, code, codeVerifier string) (string, error) {
	form := url.Values{
		"client_id":     {p.cfg.ClientID},
		"client_secret": {p.cfg.ClientSecret},
		"code":          {code},
		"grant_type":    {"authorization_code"},
		"redirect_uri":  {p.cfg.RedirectURL},
	}
	if v := strings.TrimSpace(codeVerifier); v != "" {
		form.Set("code_verifier", v)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.cfg.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrGoogleExchangeFailed, err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := p.cfg.HTTPClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrGoogleExchangeFailed, err)
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode != http.StatusOK {
		log.Printf("google oauth token exchange http status %d: %s", resp.StatusCode, string(bodyBytes))
		return "", ErrGoogleExchangeFailed
	}

	var tokResp struct {
		AccessToken      string `json:"access_token"`
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
	}
	if err := json.Unmarshal(bodyBytes, &tokResp); err != nil {
		log.Printf("google oauth token exchange json decode error: %v (raw: %s)", err, string(bodyBytes))
		return "", ErrGoogleExchangeFailed
	}
	if tokResp.Error != "" || strings.TrimSpace(tokResp.AccessToken) == "" {
		log.Printf("google oauth token exchange rejected: error=%q description=%q", tokResp.Error, tokResp.ErrorDescription)
		return "", ErrGoogleExchangeFailed
	}
	return tokResp.AccessToken, nil
}

func (p *GoogleProvider) getJSON(ctx context.Context, endpoint, accessToken string, dst any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrGoogleExchangeFailed, err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")

	resp, err := p.cfg.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrGoogleExchangeFailed, err)
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		log.Printf("google api error: endpoint=%s status=%d body=%s", endpoint, resp.StatusCode, string(bodyBytes))
		return ErrGoogleExchangeFailed
	}
	if err := json.Unmarshal(bodyBytes, dst); err != nil {
		log.Printf("google api decode error: endpoint=%s err=%v", endpoint, err)
		return ErrGoogleExchangeFailed
	}
	return nil
}
