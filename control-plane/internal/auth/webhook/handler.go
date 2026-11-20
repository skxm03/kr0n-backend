package webhook

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/skxm03/kr0n-backend/control-plane/internal/auth/repository"
)

const (
	// DefaultMaxWebhookBytes is the default maximum allowed GitHub webhook payload size (10 MB).
	DefaultMaxWebhookBytes int64 = 10 << 20
)

var (
	// ErrPayloadTooLarge indicates the webhook request body exceeded maxBytes.
	ErrPayloadTooLarge = errors.New("webhook payload too large")
	// ErrInvalidPayload indicates the webhook JSON body could not be decoded.
	ErrInvalidPayload = errors.New("invalid webhook JSON payload")
)

// InstallationManager defines the installation persistence and token cache operations required by WebhookHandler.
type InstallationManager interface {
	UpdateGitHubInstallationStatus(ctx context.Context, installationID int64, status string) (*repository.GitHubInstallation, error)
	GetGitHubInstallationByInstallationID(ctx context.Context, installationID int64) (*repository.GitHubInstallation, error)
	InvalidateGitHubInstallationToken(installationID int64)
}

// AuditRecorder records append-only audit events triggered by GitHub webhooks.
type AuditRecorder interface {
	Record(ctx context.Context, ev repository.AuditEvent) error
}

// WebhookHandler verifies and processes incoming GitHub App webhook deliveries.
type WebhookHandler struct {
	webhookSecret string
	maxBytes      int64
	installations InstallationManager
	audit         AuditRecorder
}

// NewWebhookHandler creates a new WebhookHandler.
func NewWebhookHandler(secret string, maxBytes int64, installations InstallationManager, audit AuditRecorder) *WebhookHandler {
	if maxBytes <= 0 {
		maxBytes = DefaultMaxWebhookBytes
	}
	return &WebhookHandler{
		webhookSecret: strings.TrimSpace(secret),
		maxBytes:      maxBytes,
		installations: installations,
		audit:         audit,
	}
}

// ServeHTTP handles raw HTTP `POST /api/v1/github/webhooks` requests directly.
func (h *WebhookHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, h.maxBytes+1))
	if err != nil || int64(len(body)) > h.maxBytes {
		http.Error(w, "payload too large", http.StatusRequestEntityTooLarge)
		return
	}

	sig := r.Header.Get("X-Hub-Signature-256")
	eventType := r.Header.Get("X-GitHub-Event")
	deliveryID := r.Header.Get("X-GitHub-Delivery")

	statusCode, respBody, _ := h.Process(r.Context(), eventType, deliveryID, sig, body)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_, _ = w.Write(respBody)
}

// Process verifies the HMAC-SHA256 signature on the raw body bytes and dispatches the GitHub webhook event.
func (h *WebhookHandler) Process(ctx context.Context, eventType, deliveryID, signatureHeader string, body []byte) (int, []byte, error) {
	if int64(len(body)) > h.maxBytes {
		return http.StatusRequestEntityTooLarge, []byte(`{"error":"payload too large"}`), ErrPayloadTooLarge
	}

	if err := VerifyGitHubSignature(body, signatureHeader, h.webhookSecret); err != nil {
		return http.StatusUnauthorized, []byte(`{"error":"invalid signature"}`), err
	}

	switch strings.ToLower(strings.TrimSpace(eventType)) {
	case "ping":
		return http.StatusOK, []byte(`{"status":"pong"}`), nil

	case "installation":
		var payload InstallationEventPayload
		if err := json.Unmarshal(body, &payload); err != nil {
			return http.StatusBadRequest, []byte(`{"error":"invalid payload"}`), ErrInvalidPayload
		}
		if err := h.handleInstallationEvent(ctx, deliveryID, payload); err != nil {
			log.Printf("handle installation webhook event error (delivery=%s): %v", deliveryID, err)
			return http.StatusInternalServerError, []byte(`{"error":"internal processing error"}`), err
		}

	case "installation_repositories":
		var payload InstallationRepositoriesEventPayload
		if err := json.Unmarshal(body, &payload); err != nil {
			return http.StatusBadRequest, []byte(`{"error":"invalid payload"}`), ErrInvalidPayload
		}
		if err := h.handleInstallationRepositoriesEvent(ctx, deliveryID, payload); err != nil {
			log.Printf("handle installation_repositories webhook event error (delivery=%s): %v", deliveryID, err)
			return http.StatusInternalServerError, []byte(`{"error":"internal processing error"}`), err
		}

	default:
		// Unknown event types acknowledge 200 OK so GitHub does not retry.
	}

	return http.StatusOK, []byte(`{"status":"received"}`), nil
}

func (h *WebhookHandler) handleInstallationEvent(ctx context.Context, deliveryID string, payload InstallationEventPayload) error {
	if payload.Installation.ID <= 0 {
		return ErrInvalidPayload
	}

	var (
		targetStatus string
		auditAction  string
	)
	switch strings.ToLower(strings.TrimSpace(payload.Action)) {
	case "deleted":
		targetStatus = "deleted"
		auditAction = "github.installation_deleted"
	case "suspend":
		targetStatus = "suspended"
		auditAction = "github.installation_suspended"
	case "unsuspend":
		targetStatus = "active"
		auditAction = "github.installation_unsuspended"
	default:
		return nil
	}

	if h.installations == nil {
		return nil
	}

	inst, err := h.installations.UpdateGitHubInstallationStatus(ctx, payload.Installation.ID, targetStatus)
	if err != nil {
		if errors.Is(err, repository.ErrInstallationNotFound) {
			// Acknowledge unlinked installation events gracefully after evicting any cached token.
			h.installations.InvalidateGitHubInstallationToken(payload.Installation.ID)
			return nil
		}
		return err
	}

	if h.audit != nil && inst != nil {
		orgID := inst.OrganizationID
		meta := map[string]any{
			"installation_id": payload.Installation.ID,
			"status":          targetStatus,
			"account_login":   payload.Installation.Account.Login,
			"account_type":    payload.Installation.Account.Type,
			"sender_login":    payload.Sender.Login,
		}
		if deliveryID != "" {
			meta["delivery_id"] = deliveryID
		}
		if err := h.audit.Record(ctx, repository.AuditEvent{
			OrganizationID: &orgID,
			ActorType:      repository.ActorTypeSystem,
			Action:         auditAction,
			ResourceType:   "github_installation",
			ResourceID:     strconv.FormatInt(payload.Installation.ID, 10),
			Metadata:       meta,
		}); err != nil {
			log.Printf("webhook audit event write error (%s): %v", auditAction, err)
		}
	}

	return nil
}

func (h *WebhookHandler) handleInstallationRepositoriesEvent(ctx context.Context, deliveryID string, payload InstallationRepositoriesEventPayload) error {
	if payload.Installation.ID <= 0 {
		return ErrInvalidPayload
	}

	action := strings.ToLower(strings.TrimSpace(payload.Action))
	if action != "added" && action != "removed" {
		return nil
	}

	if h.installations == nil {
		return nil
	}

	// Evict cached installation token so next VCS access rotates token and refreshes repo cache.
	h.installations.InvalidateGitHubInstallationToken(payload.Installation.ID)

	inst, err := h.installations.GetGitHubInstallationByInstallationID(ctx, payload.Installation.ID)
	if err != nil {
		if errors.Is(err, repository.ErrInstallationNotFound) {
			return nil
		}
		return err
	}

	if h.audit != nil && inst != nil {
		orgID := inst.OrganizationID
		auditAction := "github.installation_repositories_" + action

		addedNames := make([]string, 0, len(payload.RepositoriesAdded))
		for _, r := range payload.RepositoriesAdded {
			if r.FullName != "" {
				addedNames = append(addedNames, r.FullName)
			} else if r.Name != "" {
				addedNames = append(addedNames, r.Name)
			}
		}
		removedNames := make([]string, 0, len(payload.RepositoriesRemoved))
		for _, r := range payload.RepositoriesRemoved {
			if r.FullName != "" {
				removedNames = append(removedNames, r.FullName)
			} else if r.Name != "" {
				removedNames = append(removedNames, r.Name)
			}
		}

		meta := map[string]any{
			"installation_id":      payload.Installation.ID,
			"repositories_added":   addedNames,
			"repositories_removed": removedNames,
			"sender_login":         payload.Sender.Login,
		}
		if deliveryID != "" {
			meta["delivery_id"] = deliveryID
		}
		if err := h.audit.Record(ctx, repository.AuditEvent{
			OrganizationID: &orgID,
			ActorType:      repository.ActorTypeSystem,
			Action:         auditAction,
			ResourceType:   "github_installation",
			ResourceID:     strconv.FormatInt(payload.Installation.ID, 10),
			Metadata:       meta,
		}); err != nil {
			log.Printf("webhook audit event write error (%s): %v", auditAction, err)
		}
	}

	return nil
}
