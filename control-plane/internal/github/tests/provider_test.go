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

	"github.com/skxm03/kr0n-backend/control-plane/internal/github/provider"
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
	p, err := provider.NewGitHubAppProvider(provider.GitHubAppConfig{})
	if err != nil {
		t.Fatalf("unexpected error on empty config: %v", err)
	}
	if p.Configured() {
		t.Fatal("expected Configured() == false")
	}
	if _, _, err := p.StartInstallation(uuid.New(), uuid.New()); !errors.Is(err, provider.ErrGitHubAppNotConfigured) {
		t.Fatalf("expected ErrGitHubAppNotConfigured, got %v", err)
	}
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

type dummyResponseWriter struct {
	header http.Header
	code   int
	body   []byte
}

func (w *dummyResponseWriter) Header() http.Header {
	if w.header == nil {
		w.header = make(http.Header)
	}
	return w.header
}
func (w *dummyResponseWriter) Write(b []byte) (int, error) {
	w.body = append(w.body, b...)
	return len(b), nil
}
func (w *dummyResponseWriter) WriteHeader(statusCode int) {
	w.code = statusCode
}

func newHandlerClient(h http.Handler) *http.Client {
	return &http.Client{
		Transport: roundTripperFunc(func(r *http.Request) (*http.Response, error) {
			rw := &dummyResponseWriter{code: http.StatusOK}
			h.ServeHTTP(rw, r)
			return &http.Response{
				StatusCode: rw.code,
				Header:     rw.header,
				Body:       ioNopCloser(rw.body),
				Request:    r,
			}, nil
		}),
	}
}

func ioNopCloser(b []byte) ioReadCloser {
	return ioReadCloser{strings.NewReader(string(b))}
}

type ioReadCloser struct {
	*strings.Reader
}

func (ioReadCloser) Close() error { return nil }

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

	p, err := provider.NewGitHubAppProvider(provider.GitHubAppConfig{
		AppID:         "12345",
		AppSlug:       "kr0n-cloud",
		PrivateKeyPEM: pemKey,
		StateSecret:   "test-state-secret-with-sufficient-entropy-32b!",
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
	if !strings.HasPrefix(installURL, "https://github.com/apps/kr0n-cloud/installations/new?state=") {
		t.Fatalf("unexpected install url: %s", installURL)
	}

	if err := p.VerifyState(state, orgID, userID); err != nil {
		t.Fatalf("VerifyState valid: %v", err)
	}
	if err := p.VerifyState(state, uuid.New(), userID); !errors.Is(err, provider.ErrInvalidInstallationState) {
		t.Fatalf("expected ErrInvalidInstallationState on org mismatch, got %v", err)
	}

	ctx := context.Background()
	meta, err := p.GetInstallation(ctx, 849204)
	if err != nil {
		t.Fatalf("GetInstallation: %v", err)
	}
	if meta.InstallationID != 849204 || meta.AccountLogin != "kr0n-org" || meta.Status != "active" {
		t.Fatalf("unexpected installation meta: %+v", meta)
	}

	tok1, exp1, err := p.GetInstallationToken(ctx, 849204)
	if err != nil {
		t.Fatalf("GetInstallationToken first call: %v", err)
	}
	if tok1 != "ghs_inst_secret_123" || exp1.Before(time.Now().UTC()) {
		t.Fatalf("unexpected token or expiry: tok=%s, exp=%s", tok1, exp1)
	}
	if tokenMints.Load() != 1 {
		t.Fatalf("expected 1 mint call, got %d", tokenMints.Load())
	}

	// Cached token hit
	tok2, _, err := p.GetInstallationToken(ctx, 849204)
	if err != nil || tok2 != tok1 {
		t.Fatalf("cached GetInstallationToken failed: %v", err)
	}
	if tokenMints.Load() != 1 {
		t.Fatalf("expected cache hit (1 mint call), got %d", tokenMints.Load())
	}

	// Cache invalidation forces fresh mint
	p.InvalidateInstallationToken(849204)
	tok3, _, err := p.GetInstallationToken(ctx, 849204)
	if err != nil || tok3 != tok1 {
		t.Fatalf("post-invalidation GetInstallationToken failed: %v", err)
	}
	if tokenMints.Load() != 2 {
		t.Fatalf("expected 2 mint calls after invalidation, got %d", tokenMints.Load())
	}
}
