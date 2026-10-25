package oauth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/skxm03/kr0n-backend/control-plane/internal/auth/user"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func newHandlerClient(h http.Handler) *http.Client {
	return &http.Client{
		Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, r)
			return rec.Result(), nil
		}),
	}
}

func TestGitHubProvider_NotConfigured(t *testing.T) {
	p := NewGitHubProvider(GitHubConfig{})
	if p.Configured() {
		t.Fatal("expected Configured() == false")
	}
	if _, _, _, err := p.Start(); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("expected ErrNotConfigured, got %v", err)
	}
	if _, err := p.ExchangeAndFetchProfile(context.Background(), "c", "v"); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("expected ErrNotConfigured, got %v", err)
	}
}

func TestGitHubProvider_StartAndExchange(t *testing.T) {
	var lastVerifier string
	mux := http.NewServeMux()
	mux.HandleFunc("POST /login/oauth/access_token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		lastVerifier = r.FormValue("code_verifier")
		if r.FormValue("code") != "good_code" || lastVerifier == "" {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"bad_verification_code"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"gho_test_token","token_type":"bearer"}`))
	})
	mux.HandleFunc("GET /user", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer gho_test_token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(`{"id":4242,"login":"octocat","name":"The Octocat","avatar_url":"https://avatars.example/o.png"}`))
	})
	mux.HandleFunc("GET /user/emails", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`[
			{"email":"unverified@kr0n.dev","primary":true,"verified":false},
			{"email":"OCTO@kr0n.dev","primary":true,"verified":true}
		]`))
	})

	p := NewGitHubProvider(GitHubConfig{
		ClientID:     "cid",
		ClientSecret: "csecret",
		RedirectURL:  "http://localhost:8080/api/v1/auth/github/callback",
		AuthorizeURL: "http://github.local/login/oauth/authorize",
		TokenURL:     "http://github.local/login/oauth/access_token",
		APIURL:       "http://github.local",
		HTTPClient:   newHandlerClient(mux),
	})

	authURL, state, verifier, err := p.Start()
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	parsed, err := url.Parse(authURL)
	if err != nil {
		t.Fatalf("parse authURL: %v", err)
	}
	sum := sha256.Sum256([]byte(verifier))
	wantChallenge := base64.RawURLEncoding.EncodeToString(sum[:])
	if parsed.Query().Get("state") != state || parsed.Query().Get("code_challenge") != wantChallenge || parsed.Query().Get("code_challenge_method") != "S256" {
		t.Fatalf("unexpected query params: %v", parsed.Query())
	}

	prof, err := p.ExchangeAndFetchProfile(context.Background(), "good_code", verifier)
	if err != nil {
		t.Fatalf("ExchangeAndFetchProfile: %v", err)
	}
	if prof.Provider != "github" || prof.ProviderUserID != "4242" || prof.Email != "OCTO@kr0n.dev" || !prof.EmailVerified || prof.DisplayName != "The Octocat" {
		t.Fatalf("unexpected profile: %+v", prof)
	}
}

func TestGitHubProvider_RejectsUnverifiedEmail(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /login/oauth/access_token", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"access_token":"gho_test_token"}`))
	})
	mux.HandleFunc("GET /user", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"id":99,"login":"unverified"}`))
	})
	mux.HandleFunc("GET /user/emails", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`[{"email":"spoof@kr0n.dev","primary":true,"verified":false}]`))
	})

	p := NewGitHubProvider(GitHubConfig{
		ClientID:     "cid",
		ClientSecret: "csecret",
		RedirectURL:  "http://localhost:8080/api/v1/auth/github/callback",
		TokenURL:     "http://github.local/login/oauth/access_token",
		APIURL:       "http://github.local",
		HTTPClient:   newHandlerClient(mux),
	})

	_, err := p.ExchangeAndFetchProfile(context.Background(), "code", "verifier")
	if !errors.Is(err, user.ErrOAuthEmailNotVerified) {
		t.Fatalf("expected ErrOAuthEmailNotVerified, got %v", err)
	}
}
