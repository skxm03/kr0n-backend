package tests

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"testing"

	"github.com/skxm03/kr0n-backend/control-plane/internal/auth/oauth"
	"github.com/skxm03/kr0n-backend/control-plane/internal/auth/repository"
)

func TestGoogleProvider_NotConfigured(t *testing.T) {
	p := oauth.NewGoogleProvider(oauth.GoogleConfig{})
	if p.Configured() {
		t.Fatal("expected Configured() == false")
	}
	if _, _, _, err := p.Start(); !errors.Is(err, oauth.ErrGoogleNotConfigured) {
		t.Fatalf("expected ErrGoogleNotConfigured, got %v", err)
	}
	if _, err := p.ExchangeAndFetchProfile(context.Background(), "c", "v"); !errors.Is(err, oauth.ErrGoogleNotConfigured) {
		t.Fatalf("expected ErrGoogleNotConfigured, got %v", err)
	}
}

func TestGoogleProvider_StartAndExchange(t *testing.T) {
	var lastVerifier string
	mux := http.NewServeMux()
	mux.HandleFunc("POST /token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		lastVerifier = r.FormValue("code_verifier")
		if r.FormValue("code") != "good_code" || lastVerifier == "" {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"bad_verification_code"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"ya29.test_token","token_type":"bearer"}`))
	})
	mux.HandleFunc("GET /userinfo", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer ya29.test_token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(`{
			"sub":"1092837465",
			"name":"Google Tester",
			"email":"tester@gmail.com",
			"email_verified":true,
			"picture":"https://lh3.googleusercontent.com/test.png"
		}`))
	})

	p := oauth.NewGoogleProvider(oauth.GoogleConfig{
		ClientID:     "google-client-id",
		ClientSecret: "google-client-secret",
		RedirectURL:  "http://localhost:8080/api/v1/auth/google/callback",
		AuthorizeURL: "http://google.local/auth",
		TokenURL:     "http://google.local/token",
		UserInfoURL:  "http://google.local/userinfo",
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
	if parsed.Query().Get("access_type") != "offline" || parsed.Query().Get("prompt") != "select_account" {
		t.Fatalf("missing access_type or prompt params: %v", parsed.Query())
	}

	prof, err := p.ExchangeAndFetchProfile(context.Background(), "good_code", verifier)
	if err != nil {
		t.Fatalf("ExchangeAndFetchProfile: %v", err)
	}
	if prof.Provider != "google" || prof.ProviderUserID != "1092837465" || prof.Email != "tester@gmail.com" || !prof.EmailVerified || prof.DisplayName != "Google Tester" {
		t.Fatalf("unexpected profile: %+v", prof)
	}
	if prof.AvatarURL == nil || *prof.AvatarURL != "https://lh3.googleusercontent.com/test.png" {
		t.Fatalf("unexpected avatar: %v", prof.AvatarURL)
	}
	if lastVerifier != verifier {
		t.Fatalf("code_verifier mismatch: got %q, want %q", lastVerifier, verifier)
	}
}

func TestGoogleProvider_UnverifiedEmail(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /token", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"ya29.test_token","token_type":"bearer"}`))
	})
	mux.HandleFunc("GET /userinfo", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{
			"sub":"9999",
			"name":"Unverified User",
			"email":"unverified@gmail.com",
			"email_verified":false
		}`))
	})

	p := oauth.NewGoogleProvider(oauth.GoogleConfig{
		ClientID:     "google-client-id",
		ClientSecret: "google-client-secret",
		RedirectURL:  "http://localhost:8080/api/v1/auth/google/callback",
		AuthorizeURL: "http://google.local/auth",
		TokenURL:     "http://google.local/token",
		UserInfoURL:  "http://google.local/userinfo",
		HTTPClient:   newHandlerClient(mux),
	})

	_, err := p.ExchangeAndFetchProfile(context.Background(), "code", "verifier")
	if !errors.Is(err, repository.ErrOAuthEmailNotVerified) {
		t.Fatalf("expected ErrOAuthEmailNotVerified, got %v", err)
	}
}
