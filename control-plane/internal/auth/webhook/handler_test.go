package webhook

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/google/uuid"

	"github.com/skxm03/kr0n-backend/control-plane/internal/auth/repository"
)

type stubInstallationManager struct {
	mu            sync.Mutex
	installations map[int64]*repository.GitHubInstallation
	invalidated   []int64
}

func newStubInstallationManager() *stubInstallationManager {
	return &stubInstallationManager{
		installations: make(map[int64]*repository.GitHubInstallation),
	}
}

func (s *stubInstallationManager) UpdateGitHubInstallationStatus(_ context.Context, installationID int64, status string) (*repository.GitHubInstallation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	inst, ok := s.installations[installationID]
	if !ok {
		return nil, repository.ErrInstallationNotFound
	}
	inst.Status = status
	cp := *inst
	return &cp, nil
}

func (s *stubInstallationManager) GetGitHubInstallationByInstallationID(_ context.Context, installationID int64) (*repository.GitHubInstallation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	inst, ok := s.installations[installationID]
	if !ok {
		return nil, repository.ErrInstallationNotFound
	}
	cp := *inst
	return &cp, nil
}

func (s *stubInstallationManager) InvalidateGitHubInstallationToken(installationID int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.invalidated = append(s.invalidated, installationID)
}

type stubAuditRecorder struct {
	mu     sync.Mutex
	events []repository.AuditEvent
}

func (a *stubAuditRecorder) Record(_ context.Context, ev repository.AuditEvent) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.events = append(a.events, ev)
	return nil
}

func TestWebhookHandler_ServeHTTP(t *testing.T) {
	const secret = "whsec_unit_test_secret_key"
	orgID := uuid.New()
	instMgr := newStubInstallationManager()
	instMgr.installations[77001] = &repository.GitHubInstallation{
		ID:             uuid.New(),
		OrganizationID: orgID,
		InstallationID: 77001,
		AccountLogin:   "acme-gh",
		AccountType:    "Organization",
		Status:         "active",
	}
	auditRec := &stubAuditRecorder{}
	handler := NewWebhookHandler(secret, 1024, instMgr, auditRec)

	t.Run("ping event returns 200 pong", func(t *testing.T) {
		body := []byte(`{"zen":"Keep it logically awesome.","hook_id":1}`)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/github/webhooks", bytes.NewReader(body))
		req.Header.Set("X-GitHub-Event", "ping")
		req.Header.Set("X-GitHub-Delivery", "deliv-ping-1")
		req.Header.Set("X-Hub-Signature-256", signPayload(secret, body))

		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200 OK, got %d: %s", rec.Code, rec.Body.String())
		}
		if rec.Body.String() != `{"status":"pong"}` {
			t.Fatalf("expected pong body, got %s", rec.Body.String())
		}
	})

	t.Run("invalid signature returns 401 Unauthorized", func(t *testing.T) {
		body := []byte(`{"action":"deleted","installation":{"id":77001}}`)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/github/webhooks", bytes.NewReader(body))
		req.Header.Set("X-GitHub-Event", "installation")
		req.Header.Set("X-Hub-Signature-256", "sha256=0000000000000000000000000000000000000000000000000000000000000000")

		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 Unauthorized, got %d", rec.Code)
		}
	})

	t.Run("oversized payload returns 413 RequestEntityTooLarge", func(t *testing.T) {
		largeBody := bytes.Repeat([]byte("a"), 2048)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/github/webhooks", bytes.NewReader(largeBody))
		req.Header.Set("X-GitHub-Event", "ping")
		req.Header.Set("X-Hub-Signature-256", signPayload(secret, largeBody))

		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusRequestEntityTooLarge {
			t.Fatalf("expected 413 RequestEntityTooLarge, got %d", rec.Code)
		}
	})

	t.Run("installation suspend updates status and emits audit event", func(t *testing.T) {
		body := []byte(`{"action":"suspend","installation":{"id":77001,"account":{"login":"acme-gh","type":"Organization"}},"sender":{"id":1,"login":"octocat"}}`)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/github/webhooks", bytes.NewReader(body))
		req.Header.Set("X-GitHub-Event", "installation")
		req.Header.Set("X-GitHub-Delivery", "deliv-suspend-1")
		req.Header.Set("X-Hub-Signature-256", signPayload(secret, body))

		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200 OK, got %d: %s", rec.Code, rec.Body.String())
		}
		if instMgr.installations[77001].Status != "suspended" {
			t.Fatalf("expected installation status 'suspended', got %q", instMgr.installations[77001].Status)
		}
		if len(auditRec.events) != 1 || auditRec.events[0].Action != "github.installation_suspended" {
			t.Fatalf("expected github.installation_suspended audit event, got %+v", auditRec.events)
		}
	})

	t.Run("installation unsuspend restores active status", func(t *testing.T) {
		body := []byte(`{"action":"unsuspend","installation":{"id":77001,"account":{"login":"acme-gh","type":"Organization"}},"sender":{"id":1,"login":"octocat"}}`)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/github/webhooks", bytes.NewReader(body))
		req.Header.Set("X-GitHub-Event", "installation")
		req.Header.Set("X-GitHub-Delivery", "deliv-unsuspend-1")
		req.Header.Set("X-Hub-Signature-256", signPayload(secret, body))

		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK || instMgr.installations[77001].Status != "active" {
			t.Fatalf("expected active status after unsuspend, got code=%d status=%q", rec.Code, instMgr.installations[77001].Status)
		}
	})

	t.Run("installation deleted marks status deleted and records github.installation_deleted audit", func(t *testing.T) {
		body := []byte(`{"action":"deleted","installation":{"id":77001,"account":{"login":"acme-gh","type":"Organization"}},"sender":{"id":1,"login":"octocat"}}`)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/github/webhooks", bytes.NewReader(body))
		req.Header.Set("X-GitHub-Event", "installation")
		req.Header.Set("X-GitHub-Delivery", "deliv-del-1")
		req.Header.Set("X-Hub-Signature-256", signPayload(secret, body))

		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200 OK, got %d", rec.Code)
		}
		if instMgr.installations[77001].Status != "deleted" {
			t.Fatalf("expected status 'deleted', got %q", instMgr.installations[77001].Status)
		}
		lastAudit := auditRec.events[len(auditRec.events)-1]
		if lastAudit.Action != "github.installation_deleted" || lastAudit.OrganizationID == nil || *lastAudit.OrganizationID != orgID {
			t.Fatalf("unexpected audit event: %+v", lastAudit)
		}
	})

	t.Run("installation_repositories added invalidates token cache and audits repositories", func(t *testing.T) {
		body := []byte(`{"action":"added","installation":{"id":77001},"repositories_added":[{"id":10,"name":"api","full_name":"acme-gh/api"}],"sender":{"id":1,"login":"octocat"}}`)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/github/webhooks", bytes.NewReader(body))
		req.Header.Set("X-GitHub-Event", "installation_repositories")
		req.Header.Set("X-GitHub-Delivery", "deliv-repos-1")
		req.Header.Set("X-Hub-Signature-256", signPayload(secret, body))

		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200 OK, got %d", rec.Code)
		}
		lastAudit := auditRec.events[len(auditRec.events)-1]
		if lastAudit.Action != "github.installation_repositories_added" {
			t.Fatalf("expected github.installation_repositories_added audit, got %+v", lastAudit)
		}
	})
}
