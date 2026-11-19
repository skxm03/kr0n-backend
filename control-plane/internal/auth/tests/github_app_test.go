package tests

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/skxm03/kr0n-backend/control-plane/internal/auth/oauth"
)

func generateTestRSAPEM(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}
	der := x509.MarshalPKCS1PrivateKey(key)
	block := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: der}
	return string(pem.EncodeToMemory(block))
}

func TestGitHubAppProvider_NotConfigured(t *testing.T) {
	p, err := oauth.NewGitHubAppProvider(oauth.GitHubAppConfig{})
	if err != nil {
		t.Fatalf("unexpected error on empty config: %v", err)
	}
	if p.Configured() {
		t.Fatal("expected Configured() == false")
	}
	if _, _, err := p.StartInstallation(uuid.New(), uuid.New()); !errors.Is(err, oauth.ErrGitHubAppNotConfigured) {
		t.Fatalf("expected ErrGitHubAppNotConfigured, got %v", err)
	}
}

func TestGitHubAppProvider_StateAndExplorer(t *testing.T) {
	pemKey := generateTestRSAPEM(t)
	var tokenMints atomic.Int32

	mux := http.NewServeMux()
	mux.HandleFunc("GET /app/installations/849204", func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Bearer eyJ") {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(`{
			"id": 849204,
			"repository_selection": "all",
			"account": {"login": "kr0n-org", "type": "Organization"},
			"suspended_at": null
		}`))
	})
	mux.HandleFunc("POST /app/installations/849204/access_tokens", func(w http.ResponseWriter, r *http.Request) {
		tokenMints.Add(1)
		w.WriteHeader(http.StatusCreated)
		exp := time.Now().UTC().Add(time.Hour).Format(time.RFC3339)
		_, _ = w.Write([]byte(`{"token":"ghs_inst_secret_123","expires_at":"` + exp + `"}`))
	})
	mux.HandleFunc("GET /installation/repositories", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer ghs_inst_secret_123" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(`{
			"total_count": 2,
			"repositories": [
				{
					"id": 1001,
					"name": "orvea-core",
					"full_name": "kr0n-org/orvea-core",
					"private": true,
					"default_branch": "main",
					"html_url": "https://github.com/kr0n-org/orvea-core"
				},
				{
					"id": 1002,
					"name": "orvea-web",
					"full_name": "kr0n-org/orvea-web",
					"private": false,
					"default_branch": "develop",
					"html_url": "https://github.com/kr0n-org/orvea-web"
				}
			]
		}`))
	})
	mux.HandleFunc("GET /repos/kr0n-org/orvea-core/branches", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer ghs_inst_secret_123" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(`[
			{"name":"main","commit":{"sha":"a83f2c1"},"protected":true},
			{"name":"staging","commit":{"sha":"f1c2a8b"},"protected":false}
		]`))
	})
	mux.HandleFunc("GET /repos/kr0n-org/orvea-core/git/trees/main", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer ghs_inst_secret_123" || r.URL.Query().Get("recursive") != "1" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		_, _ = w.Write([]byte(`{
			"sha": "a83f2c1",
			"tree": [
				{"path": "README.md", "type": "blob"},
				{"path": "apps", "type": "tree"},
				{"path": "apps/api", "type": "tree"},
				{"path": "apps/api/main.go", "type": "blob"},
				{"path": "apps/web", "type": "tree"},
				{"path": ".github", "type": "tree"},
				{"path": ".github/workflows", "type": "tree"}
			]
		}`))
	})

	p, err := oauth.NewGitHubAppProvider(oauth.GitHubAppConfig{
		AppID:         "998877",
		AppSlug:       "kr0n-paas",
		PrivateKeyPEM: pemKey,
		StateSecret:   "state-signing-secret-key",
		APIURL:        "http://github.local",
		HTTPClient:    newHandlerClient(mux),
	})
	if err != nil {
		t.Fatalf("NewGitHubAppProvider: %v", err)
	}

	orgID := uuid.New()
	userID := uuid.New()
	installURL, state, err := p.StartInstallation(orgID, userID)
	if err != nil {
		t.Fatalf("StartInstallation: %v", err)
	}
	if !strings.HasPrefix(installURL, "https://github.com/apps/kr0n-paas/installations/new?state=") {
		t.Fatalf("unexpected installURL: %s", installURL)
	}

	if err := p.VerifyState(state, orgID, userID); err != nil {
		t.Fatalf("VerifyState failed: %v", err)
	}
	if err := p.VerifyState(state, uuid.New(), userID); !errors.Is(err, oauth.ErrInvalidInstallationState) {
		t.Fatalf("expected ErrInvalidInstallationState for wrong orgID, got %v", err)
	}
	if err := p.VerifyState(state+"tamper", orgID, userID); !errors.Is(err, oauth.ErrInvalidInstallationState) {
		t.Fatalf("expected ErrInvalidInstallationState for tampered state, got %v", err)
	}

	ctx := context.Background()
	inst, err := p.GetInstallation(ctx, 849204)
	if err != nil {
		t.Fatalf("GetInstallation: %v", err)
	}
	if inst.InstallationID != 849204 || inst.AccountLogin != "kr0n-org" || inst.AccountType != "Organization" || inst.RepositorySelection != "all" || inst.Status != "active" {
		t.Fatalf("unexpected installation: %+v", inst)
	}

	tok, exp, err := p.GetInstallationToken(ctx, 849204)
	if err != nil {
		t.Fatalf("GetInstallationToken: %v", err)
	}
	if tok != "ghs_inst_secret_123" || exp.IsZero() {
		t.Fatalf("unexpected token=%q, exp=%v", tok, exp)
	}

	// Calling GetInstallationToken again within cache TTL should hit cache without issuing new HTTP mint
	tok2, _, err := p.GetInstallationToken(ctx, 849204)
	if err != nil {
		t.Fatalf("GetInstallationToken cached: %v", err)
	}
	if tok2 != tok {
		t.Fatalf("expected token %q, got %q", tok, tok2)
	}

	if got := tokenMints.Load(); got != 1 {
		t.Fatalf("expected 1 installation token mint (cached), got %d", got)
	}
}
