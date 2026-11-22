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

	"github.com/skxm03/kr0n-backend/control-plane/internal/github/domain"
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
	UpdateGitHubInstallationStatus(ctx context.Context, installationID int64, status string) (*domain.GitHubInstallation, error)
	GetGitHubInstallationByInstallationID(ctx context.Context, installationID int64) (*domain.GitHubInstallation, error)
	InvalidateGitHubInstallationToken(installationID int64)
}

// AuditRecorder records append-only audit events triggered by GitHub webhooks.
type AuditRecorder interface {
	Record(ctx context.Context, orgID string, action, resourceType, resourceID string, meta map[string]any) error
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
		if errors.Is(err, domain.ErrInstallationNotFound) {
			// Acknowledge unlinked installation events gracefully after evicting any cached token.
			h.installations.InvalidateGitHubInstallationToken(payload.Installation.ID)
			return nil
		}
		return err
	}

	if h.audit != nil && inst != nil {
		orgID := inst.OrganizationID.String()
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
		if err := h.audit.Record(ctx, orgID, auditAction, "github_installation", strconv.FormatInt(payload.Installation.ID, 10), meta); err != nil {
			log.Printf("audit record error for webhook event %s: %v", auditAction, err)
		}
	}

	return nil
}

func (h *WebhookHandler) handleInstallationRepositoriesEvent(ctx context.Context, deliveryID string, payload InstallationRepositoriesEventPayload) error {
	if payload.Installation.ID <= 0 {
		return ErrInvalidPayload
	}

	if h.installations == nil {
		return nil
	}

	// Any modification to linked repositories (added/removed) invalidates the cached installation token
	// so the next repository exploration call mints a fresh token reflecting updated permissions.
	h.installations.InvalidateGitHubInstallationToken(payload.Installation.ID)

	inst, err := h.installations.GetGitHubInstallationByInstallationID(ctx, payload.Installation.ID)
	if err != nil {
		if errors.Is(err, domain.ErrInstallationNotFound) {
			return nil
		}
		return err
	}

	if h.audit != nil && inst != nil {
		orgID := inst.OrganizationID.String()
		meta := map[string]any{
			"installation_id":      payload.Installation.ID,
			"action":               payload.Action,
			"repository_selection": payload.RepositorySelection,
			"sender_login":         payload.Sender.Login,
			"added_count":          len(payload.RepositoriesAdded),
			"removed_count":        len(payload.RepositoriesRemoved),
		}
		if deliveryID != "" {
			meta["delivery_id"] = deliveryID
		}
		if err := h.audit.Record(ctx, orgID, "github.installation_repositories_updated", "github_installation", strconv.FormatInt(payload.Installation.ID, 10), meta); err != nil {
			log.Printf("audit record error for installation_repositories webhook: %v", err)
		}
	}

	return nil
}
