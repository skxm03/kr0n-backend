package tests

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"testing"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	authv1 "github.com/skxm03/kr0n-backend/control-plane/gen/auth/v1"
	githubv1 "github.com/skxm03/kr0n-backend/control-plane/gen/github/v1"
	"github.com/skxm03/kr0n-backend/control-plane/internal/github/handlers"
	"github.com/skxm03/kr0n-backend/control-plane/internal/github/provider"
	"github.com/skxm03/kr0n-backend/control-plane/internal/github/service"
	"github.com/skxm03/kr0n-backend/control-plane/internal/github/webhook"
)

func TestHandlers_GitHubInstallationAndWebhooks(t *testing.T) {
	ctx := context.Background()

	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privKey),
	})

	ghMux := http.NewServeMux()
	ghMux.HandleFunc("GET /app/installations/77001", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id":                   77001,
			"repository_selection": "all",
			"account": map[string]any{
				"login": "acme-gh",
				"type":  "Organization",
			},
		})
	})
	ghMux.HandleFunc("POST /app/installations/77001/access_tokens", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"token":      "ghs_install_token_77001",
			"expires_at": "2099-01-01T00:00:00Z",
		})
	})

	ghApp, err := provider.NewGitHubAppProvider(provider.GitHubAppConfig{
		AppID:         "12345",
		AppSlug:       "kr0n-cloud",
		PrivateKeyPEM: string(pemBytes),
		StateSecret:   "state-secret-key-32-bytes-minimum!!",
		APIURL:        "http://github.local",
		HTTPClient:    newHandlerClient(ghMux),
	})
	if err != nil {
		t.Fatalf("NewGitHubAppProvider: %v", err)
	}

	repo := newMockInstallationRepo()
	authorizer := &testAuthorizer{
		permissions: make(map[string]map[string]bool),
	}

	svc := service.NewService(
		service.WithAuthorizer(authorizer),
		service.WithGitHubApp(ghApp),
		service.WithInstallationRepository(repo),
	)

	const webhookSecret = "whsec_integration_test_secret"
	wh := webhook.NewWebhookHandler(webhookSecret, 0, svc, nil)
	service.WithWebhookHandler(wh)(svc)

	srv := handlers.NewServer(svc)

	orgID := uuid.New()
	otherOrgID := uuid.New()
	ownerID := uuid.New()
	memberID := uuid.New()
	outsiderID := uuid.New()

	authorizer.grant(ownerID.String(), orgID.String(), "org:update", "org:read", "service:read")
	authorizer.grant(memberID.String(), orgID.String(), "org:read", "service:read")
	authorizer.grant(outsiderID.String(), otherOrgID.String(), "org:update", "org:read", "service:read")

	ownerPrincipal := &authv1.CallerPrincipal{UserId: ownerID.String(), Kind: "session"}
	memberPrincipal := &authv1.CallerPrincipal{UserId: memberID.String(), Kind: "session"}
	outsiderPrincipal := &authv1.CallerPrincipal{UserId: outsiderID.String(), Kind: "session"}

	// 1. StartGitHubInstallation requires org:update
	if _, err := srv.StartGitHubInstallation(ctx, &githubv1.StartGitHubInstallationRequest{
		Caller: memberPrincipal,
		OrgId:  orgID.String(),
	}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("expected PermissionDenied for member StartGitHubInstallation, got %v", err)
	}

	startResp, err := srv.StartGitHubInstallation(ctx, &githubv1.StartGitHubInstallationRequest{
		Caller: ownerPrincipal,
		OrgId:  orgID.String(),
	})
	if err != nil {
		t.Fatalf("StartGitHubInstallation: %v", err)
	}
	if startResp.GetState() == "" || startResp.GetInstallUrl() == "" {
		t.Fatalf("expected non-empty state and install_url, got %+v", startResp)
	}

	// 2. CompleteGitHubInstallation rejects tampered state, links installation on valid state
	if _, err := srv.CompleteGitHubInstallation(ctx, &githubv1.CompleteGitHubInstallationRequest{
		Caller:         ownerPrincipal,
		OrgId:          orgID.String(),
		InstallationId: 77001,
		State:          startResp.GetState() + "tampered",
	}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("expected InvalidArgument on tampered state, got %v", err)
	}

	completeResp, err := srv.CompleteGitHubInstallation(ctx, &githubv1.CompleteGitHubInstallationRequest{
		Caller:         ownerPrincipal,
		OrgId:          orgID.String(),
		InstallationId: 77001,
		State:          startResp.GetState(),
	})
	if err != nil {
		t.Fatalf("CompleteGitHubInstallation: %v", err)
	}
	if completeResp.GetInstallation().GetInstallationId() != 77001 || completeResp.GetInstallation().GetAccountLogin() != "acme-gh" {
		t.Fatalf("unexpected installation response: %+v", completeResp.GetInstallation())
	}

	// 3. ListGitHubInstallations allows member and denies outsider
	if _, err := srv.ListGitHubInstallations(ctx, &githubv1.ListGitHubInstallationsRequest{
		Caller: outsiderPrincipal,
		OrgId:  orgID.String(),
	}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("expected PermissionDenied for outsider ListGitHubInstallations, got %v", err)
	}
	listInstResp, err := srv.ListGitHubInstallations(ctx, &githubv1.ListGitHubInstallationsRequest{
		Caller: memberPrincipal,
		OrgId:  orgID.String(),
	})
	if err != nil || len(listInstResp.GetInstallations()) != 1 {
		t.Fatalf("ListGitHubInstallations: err=%v, resp=%+v", err, listInstResp)
	}

	// 4. GetGitHubInstallationToken allowed for member
	tokResp, err := srv.GetGitHubInstallationToken(ctx, &githubv1.GetGitHubInstallationTokenRequest{
		Caller:         memberPrincipal,
		OrgId:          orgID.String(),
		InstallationId: 77001,
	})
	if err != nil || tokResp.GetToken() != "ghs_install_token_77001" || tokResp.GetInstallationId() != 77001 || tokResp.GetExpiresAtUnix() <= 0 {
		t.Fatalf("GetGitHubInstallationToken: err=%v, resp=%+v", err, tokResp)
	}

	// 5. HandleGitHubWebhook: ping, signature verification, suspend, unsuspend
	sign := func(b []byte) string {
		mac := hmac.New(sha256.New, []byte(webhookSecret))
		mac.Write(b)
		return "sha256=" + hex.EncodeToString(mac.Sum(nil))
	}

	pingPayload := []byte(`{"zen":"Keep it logically awesome."}`)
	pingResp, err := srv.HandleGitHubWebhook(ctx, &githubv1.HandleGitHubWebhookRequest{
		Payload:         pingPayload,
		SignatureHeader: sign(pingPayload),
		EventType:       "ping",
		DeliveryId:      "deliv-ping-1",
	})
	if err != nil || pingResp.GetStatus() != "received" && pingResp.GetStatus() != "pong" {
		t.Fatalf("HandleGitHubWebhook ping: err=%v resp=%+v", err, pingResp)
	}

	// Invalid signature returns Unauthenticated
	if _, err := srv.HandleGitHubWebhook(ctx, &githubv1.HandleGitHubWebhookRequest{
		Payload:         pingPayload,
		SignatureHeader: "sha256=badbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbad",
		EventType:       "ping",
	}); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("expected Unauthenticated for bad signature, got %v", err)
	}

	// Suspend installation
	suspendPayload := []byte(`{
		"action": "suspend",
		"installation": {
			"id": 77001,
			"account": {"login": "acme-gh", "type": "Organization"}
		},
		"sender": {"id": 1, "login": "octocat"}
	}`)
	if _, err := srv.HandleGitHubWebhook(ctx, &githubv1.HandleGitHubWebhookRequest{
		Payload:         suspendPayload,
		SignatureHeader: sign(suspendPayload),
		EventType:       "installation",
		DeliveryId:      "deliv-suspend-1",
	}); err != nil {
		t.Fatalf("HandleGitHubWebhook suspend: %v", err)
	}

	// Suspended installation rejects token generation
	if _, err := srv.GetGitHubInstallationToken(ctx, &githubv1.GetGitHubInstallationTokenRequest{
		Caller:         memberPrincipal,
		OrgId:          orgID.String(),
		InstallationId: 77001,
	}); status.Code(err) != codes.NotFound {
		t.Fatalf("expected NotFound after suspend, got %v", err)
	}

	// Unsuspend installation restores active state
	unsuspendPayload := []byte(`{
		"action": "unsuspend",
		"installation": {
			"id": 77001,
			"account": {"login": "acme-gh", "type": "Organization"}
		},
		"sender": {"id": 1, "login": "octocat"}
	}`)
	if _, err := srv.HandleGitHubWebhook(ctx, &githubv1.HandleGitHubWebhookRequest{
		Payload:         unsuspendPayload,
		SignatureHeader: sign(unsuspendPayload),
		EventType:       "installation",
		DeliveryId:      "deliv-unsuspend-1",
	}); err != nil {
		t.Fatalf("HandleGitHubWebhook unsuspend: %v", err)
	}

	tokRestored, err := srv.GetGitHubInstallationToken(ctx, &githubv1.GetGitHubInstallationTokenRequest{
		Caller:         memberPrincipal,
		OrgId:          orgID.String(),
		InstallationId: 77001,
	})
	if err != nil || tokRestored.GetToken() != "ghs_install_token_77001" {
		t.Fatalf("GetGitHubInstallationToken after unsuspend: err=%v resp=%+v", err, tokRestored)
	}

	// 6. DisconnectGitHubInstallation unlinks
	if _, err := srv.DisconnectGitHubInstallation(ctx, &githubv1.DisconnectGitHubInstallationRequest{
		Caller:         ownerPrincipal,
		OrgId:          orgID.String(),
		InstallationId: 77001,
	}); err != nil {
		t.Fatalf("DisconnectGitHubInstallation: %v", err)
	}

	listAfterDisconnect, err := srv.ListGitHubInstallations(ctx, &githubv1.ListGitHubInstallationsRequest{
		Caller: memberPrincipal,
		OrgId:  orgID.String(),
	})
	if err != nil || len(listAfterDisconnect.GetInstallations()) != 0 {
		t.Fatalf("expected 0 installations after disconnect, got %+v", listAfterDisconnect)
	}
}

type testAuthorizer struct {
	permissions map[string]map[string]bool
}

func (a *testAuthorizer) grant(userID, orgID string, perms ...string) {
	key := userID + ":" + orgID
	if a.permissions[key] == nil {
		a.permissions[key] = make(map[string]bool)
	}
	for _, p := range perms {
		a.permissions[key][p] = true
	}
}

func (a *testAuthorizer) CheckPermission(ctx context.Context, caller *authv1.CallerPrincipal, orgID, permission string) (bool, error) {
	if caller == nil {
		return false, nil
	}
	key := caller.GetUserId() + ":" + orgID
	return a.permissions[key][permission], nil
}
