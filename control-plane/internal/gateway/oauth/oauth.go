package oauth

import (
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/skxm03/kr0n-backend/control-plane/internal/gateway/dynamic/config"
)

const (
	DefaultFrontendURL     = "http://localhost:3000"
	AccessTokenCookieName  = "access_token"
	RefreshTokenCookieName = "refresh_token"
	GitHubVerifierCookie   = "github_oauth_verifier"
	GoogleVerifierCookie   = "google_oauth_verifier"
)

// FrontendURL returns the configured FRONTEND_URL or default "http://localhost:3000",
// ensuring trailing slashes are trimmed.
func FrontendURL() string {
	u := strings.TrimSpace(os.Getenv("FRONTEND_URL"))
	if u == "" {
		return DefaultFrontendURL
	}
	return strings.TrimRight(u, "/")
}

// FrontendRedirectURL constructs a redirect target URL for the given path on the frontend,
// appending rawQuery if present.
func FrontendRedirectURL(path string, rawQuery string) string {
	base := FrontendURL()
	if path != "" && !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	target := fmt.Sprintf("%s%s", base, path)
	if rawQuery != "" {
		target += "?" + rawQuery
	}
	return target
}

// RedirectToFrontend writes an HTTP 302 redirect to the specified frontend path with query params preserved.
func RedirectToFrontend(w http.ResponseWriter, r *http.Request, path string) {
	http.Redirect(w, r, FrontendRedirectURL(path, r.URL.RawQuery), http.StatusFound)
}

// IsGitHubAppInstallation reports whether the HTTP request query indicates a GitHub App
// installation or setup redirect from GitHub (containing "installation_id" or "setup_action").
func IsGitHubAppInstallation(r *http.Request) bool {
	q := r.URL.Query()
	return q.Get("installation_id") != "" || q.Get("setup_action") != ""
}

// GitHubAppRedirectHandler intercepts GitHub App post-installation redirects landing on
// the OAuth callback endpoint and redirects them to the frontend app callback page.
func GitHubAppRedirectHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if IsGitHubAppInstallation(r) {
			RedirectToFrontend(w, r, "/github/callback")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// SetAuthCookies writes HttpOnly, SameSite cookies for access_token and refresh_token,
// ensuring tokens are never exposed in JavaScript or HTTP response bodies (mitigating XSS).
func SetAuthCookies(w http.ResponseWriter, accessToken, refreshToken string) {
	if accessToken != "" {
		http.SetCookie(w, &http.Cookie{
			Name:     AccessTokenCookieName,
			Value:    accessToken,
			Path:     "/",
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
			MaxAge:   900, // 15 minutes default
		})
	}
	if refreshToken != "" {
		http.SetCookie(w, &http.Cookie{
			Name:     RefreshTokenCookieName,
			Value:    refreshToken,
			Path:     "/",
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
			MaxAge:   30 * 24 * 3600, // 30 days
		})
	}
}

// ClearAuthCookies invalidates access_token and refresh_token cookies upon logout.
func ClearAuthCookies(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     AccessTokenCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
		Expires:  time.Unix(0, 0),
	})
	http.SetCookie(w, &http.Cookie{
		Name:     RefreshTokenCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
		Expires:  time.Unix(0, 0),
	})
}

// ClearVerifierCookie wipes the OAuth PKCE code verifier cookie.
func ClearVerifierCookie(w http.ResponseWriter, cookieName string) {
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
		Expires:  time.Unix(0, 0),
	})
}

// SetVerifierCookie sets the short-lived PKCE code verifier cookie for OAuth flow.
func SetVerifierCookie(w http.ResponseWriter, cookieName, verifier string) {
	if verifier != "" {
		http.SetCookie(w, &http.Cookie{
			Name:     cookieName,
			Value:    verifier,
			Path:     "/",
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
			MaxAge:   600, // 10 minutes
		})
	}
}

// HandleOAuthCompletion encapsulates setting HttpOnly tokens, clearing the PKCE verifier,
// and issuing a 302 redirect back to the frontend.
func HandleOAuthCompletion(w http.ResponseWriter, accessToken, refreshToken, verifierCookie string) {
	if accessToken != "" || refreshToken != "" {
		SetAuthCookies(w, accessToken, refreshToken)
	}
	if verifierCookie != "" {
		ClearVerifierCookie(w, verifierCookie)
	}
	w.Header().Set("Location", FrontendURL())
	w.WriteHeader(http.StatusFound)
}

// DefaultRedirects returns the built-in convenience redirect routes (e.g. /github/callback).
func DefaultRedirects() []config.RedirectConfig {
	return []config.RedirectConfig{
		{
			Path:   "/github/callback",
			Target: "/github/callback",
		},
	}
}
