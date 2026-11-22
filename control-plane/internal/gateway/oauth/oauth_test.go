package oauth

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestFrontendURL_DefaultsAndTrimming(t *testing.T) {
	t.Run("default when empty", func(t *testing.T) {
		t.Setenv("FRONTEND_URL", "")
		if got := FrontendURL(); got != "http://localhost:3000" {
			t.Fatalf("expected default %q, got %q", "http://localhost:3000", got)
		}
	})

	t.Run("trims trailing slash", func(t *testing.T) {
		t.Setenv("FRONTEND_URL", "https://app.kr0n.dev/")
		if got := FrontendURL(); got != "https://app.kr0n.dev" {
			t.Fatalf("expected trimmed %q, got %q", "https://app.kr0n.dev", got)
		}
	})

	t.Run("trims multiple trailing slashes and whitespace", func(t *testing.T) {
		t.Setenv("FRONTEND_URL", "  https://app.kr0n.dev///  ")
		if got := FrontendURL(); got != "https://app.kr0n.dev" {
			t.Fatalf("expected trimmed %q, got %q", "https://app.kr0n.dev", got)
		}
	})
}

func TestFrontendRedirectURL(t *testing.T) {
	t.Setenv("FRONTEND_URL", "https://app.kr0n.dev")

	tests := []struct {
		name     string
		path     string
		rawQuery string
		want     string
	}{
		{
			name:     "path with slash and no query",
			path:     "/github/callback",
			rawQuery: "",
			want:     "https://app.kr0n.dev/github/callback",
		},
		{
			name:     "path without leading slash",
			path:     "github/callback",
			rawQuery: "",
			want:     "https://app.kr0n.dev/github/callback",
		},
		{
			name:     "path with query string preserved",
			path:     "/github/callback",
			rawQuery: "installation_id=12345&setup_action=install",
			want:     "https://app.kr0n.dev/github/callback?installation_id=12345&setup_action=install",
		},
		{
			name:     "empty path with query string",
			path:     "",
			rawQuery: "state=abc",
			want:     "https://app.kr0n.dev?state=abc",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := FrontendRedirectURL(tc.path, tc.rawQuery)
			if got != tc.want {
				t.Fatalf("expected %q, got %q", tc.want, got)
			}
		})
	}
}

func TestIsGitHubAppInstallation(t *testing.T) {
	tests := []struct {
		name string
		url  string
		want bool
	}{
		{
			name: "installation_id present",
			url:  "http://gateway/callback?installation_id=987654",
			want: true,
		},
		{
			name: "setup_action present",
			url:  "http://gateway/callback?setup_action=install",
			want: true,
		},
		{
			name: "both present",
			url:  "http://gateway/callback?installation_id=987654&setup_action=install&state=xyz",
			want: true,
		},
		{
			name: "oauth code only (not app installation)",
			url:  "http://gateway/callback?code=gh_auth_code&state=xyz",
			want: false,
		},
		{
			name: "empty query",
			url:  "http://gateway/callback",
			want: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tc.url, nil)
			if got := IsGitHubAppInstallation(req); got != tc.want {
				t.Fatalf("expected %v, got %v", tc.want, got)
			}
		})
	}
}

func TestGitHubAppRedirectHandler(t *testing.T) {
	t.Setenv("FRONTEND_URL", "https://dashboard.kr0n.dev")

	t.Run("intercepts installation redirect", func(t *testing.T) {
		nextCalled := false
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			nextCalled = true
		})

		handler := GitHubAppRedirectHandler(next)
		req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/github/callback?installation_id=555&setup_action=install", nil)
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		if nextCalled {
			t.Fatal("expected next handler NOT to be called for installation redirect")
		}
		if rec.Code != http.StatusFound {
			t.Fatalf("expected 302 Found, got %d", rec.Code)
		}
		expectedLoc := "https://dashboard.kr0n.dev/github/callback?installation_id=555&setup_action=install"
		if got := rec.Header().Get("Location"); got != expectedLoc {
			t.Fatalf("expected Location %q, got %q", expectedLoc, got)
		}
	})

	t.Run("passes through oauth code callback", func(t *testing.T) {
		nextCalled := false
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			nextCalled = true
			w.WriteHeader(http.StatusOK)
		})

		handler := GitHubAppRedirectHandler(next)
		req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/github/callback?code=valid_code&state=random_state", nil)
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		if !nextCalled {
			t.Fatal("expected next handler to be called for oauth code callback")
		}
		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200 OK, got %d", rec.Code)
		}
	})
}

func TestHandleOAuthCompletion(t *testing.T) {
	t.Setenv("FRONTEND_URL", "https://app.kr0n.io")

	rec := httptest.NewRecorder()
	HandleOAuthCompletion(rec, "acc-token-123", "ref-token-456", "github_oauth_verifier")

	if rec.Code != http.StatusFound {
		t.Fatalf("expected 302 Found, got %d", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "https://app.kr0n.io" {
		t.Fatalf("expected redirect to https://app.kr0n.io, got %q", loc)
	}

	cookies := rec.Result().Cookies()
	cookieMap := make(map[string]*http.Cookie)
	for _, c := range cookies {
		cookieMap[c.Name] = c
	}

	// Verify access_token cookie
	acc, ok := cookieMap[AccessTokenCookieName]
	if !ok || acc.Value != "acc-token-123" || !acc.HttpOnly || acc.MaxAge <= 0 {
		t.Fatalf("invalid access_token cookie: %+v", acc)
	}

	// Verify refresh_token cookie
	ref, ok := cookieMap[RefreshTokenCookieName]
	if !ok || ref.Value != "ref-token-456" || !ref.HttpOnly || ref.MaxAge <= 0 {
		t.Fatalf("invalid refresh_token cookie: %+v", ref)
	}

	// Verify verifier cookie was cleared
	ver, ok := cookieMap["github_oauth_verifier"]
	if !ok || ver.Value != "" || ver.MaxAge != -1 {
		t.Fatalf("expected github_oauth_verifier to be cleared, got %+v", ver)
	}
}
