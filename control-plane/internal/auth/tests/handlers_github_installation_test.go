package tests

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"testing"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	authv1 "github.com/skxm03/kr0n-backend/control-plane/gen/auth/v1"
	"github.com/skxm03/kr0n-backend/control-plane/internal/auth/handlers"
	"github.com/skxm03/kr0n-backend/control-plane/internal/auth/oauth"
	"github.com/skxm03/kr0n-backend/control-plane/internal/auth/repository"
	"github.com/skxm03/kr0n-backend/control-plane/internal/auth/service"
)

func TestHandlers_GitHubInstallationAndRepoExplorer(t *testing.T) {
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
	ghMux.HandleFunc("GET /installation/repositories", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"total_count": 1,
			"repositories": []map[string]any{
				{
					"id":             501,
					"name":           "monorepo",
					"full_name":      "acme-gh/monorepo",
					"private":        true,
					"default_branch": "main",
					"html_url":       "https://github.com/acme-gh/monorepo",
					"owner":          map[string]any{"login": "acme-gh"},
				},
			},
		})
	})
	ghMux.HandleFunc("GET /repos/acme-gh/monorepo/branches", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode([]map[string]any{
			{
				"name":      "main",
				"protected": true,
				"commit":    map[string]any{"sha": "deadbeef1234"},
			},
		})
	})
	ghMux.HandleFunc("GET /repos/acme-gh/monorepo/git/trees/main", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"sha": "deadbeef1234",
			"tree": []map[string]any{
				{"path": "apps", "type": "tree"},
				{"path": "apps/api", "type": "tree"},
				{"path": "apps/web", "type": "tree"},
				{"path": "README.md", "type": "blob"},
			},
		})
	})

	ghApp, err := oauth.NewGitHubAppProvider(oauth.GitHubAppConfig{
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

	orgRepo := newMemOrgRepo()
	auditRepo := &memAuditRepo{}
	orgSvc := service.NewOrgService(orgRepo, service.WithGitHubApp(ghApp))
	auditSvc := service.NewAuditService(auditRepo)
	srv := handlers.NewServer(nil, nil, handlers.WithOrgService(orgSvc), handlers.WithAuditService(auditSvc))

	ownerID := uuid.New()
	memberID := uuid.New()
	outsiderID := uuid.New()
	orgRepo.usersByMail["member@kr0n.dev"] = memberID

	org, err := orgSvc.CreateOrg(ctx, ownerID, "Acme", "acme")
	if err != nil {
		t.Fatalf("CreateOrg: %v", err)
	}
	ownerPrincipal := &authv1.CallerPrincipal{UserId: ownerID.String(), Kind: "session"}
	memberPrincipal := &authv1.CallerPrincipal{UserId: memberID.String(), Kind: "session"}
	outsiderPrincipal := &authv1.CallerPrincipal{UserId: outsiderID.String(), Kind: "session"}

	if _, err := orgSvc.AddMember(ctx, repository.Principal{UserID: ownerID, Kind: "session"}, org.ID, "member@kr0n.dev", "member"); err != nil {
		t.Fatalf("AddMember: %v", err)
	}

	// 1. StartGitHubInstallation requires org:update
	if _, err := srv.StartGitHubInstallation(ctx, &authv1.StartGitHubInstallationRequest{
		Caller: memberPrincipal,
		OrgId:  org.ID.String(),
	}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("expected PermissionDenied for member StartGitHubInstallation, got %v", err)
	}

	startResp, err := srv.StartGitHubInstallation(ctx, &authv1.StartGitHubInstallationRequest{
		Caller: ownerPrincipal,
		OrgId:  org.ID.String(),
	})
	if err != nil {
		t.Fatalf("StartGitHubInstallation: %v", err)
	}
	if startResp.GetState() == "" || startResp.GetInstallUrl() == "" {
		t.Fatalf("expected non-empty state and install_url, got %+v", startResp)
	}

	// 2. CompleteGitHubInstallation rejects tampered state, links installation on valid state, records audit
	if _, err := srv.CompleteGitHubInstallation(ctx, &authv1.CompleteGitHubInstallationRequest{
		Caller:         ownerPrincipal,
		OrgId:          org.ID.String(),
		InstallationId: 77001,
		State:          startResp.GetState() + "tampered",
	}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("expected InvalidArgument on tampered state, got %v", err)
	}

	completeResp, err := srv.CompleteGitHubInstallation(ctx, &authv1.CompleteGitHubInstallationRequest{
		Caller:         ownerPrincipal,
		OrgId:          org.ID.String(),
		InstallationId: 77001,
		State:          startResp.GetState(),
	})
	if err != nil {
		t.Fatalf("CompleteGitHubInstallation: %v", err)
	}
	if completeResp.GetInstallation().GetInstallationId() != 77001 || completeResp.GetInstallation().GetAccountLogin() != "acme-gh" {
		t.Fatalf("unexpected installation response: %+v", completeResp.GetInstallation())
	}

	// Cross-org uniqueness check: another org cannot claim installation 77001
	otherOrg, err := orgSvc.CreateOrg(ctx, outsiderID, "Other", "other")
	if err != nil {
		t.Fatalf("CreateOrg other: %v", err)
	}
	otherStart, err := srv.StartGitHubInstallation(ctx, &authv1.StartGitHubInstallationRequest{
		Caller: outsiderPrincipal,
		OrgId:  otherOrg.ID.String(),
	})
	if err != nil {
		t.Fatalf("StartGitHubInstallation other: %v", err)
	}
	if _, err := srv.CompleteGitHubInstallation(ctx, &authv1.CompleteGitHubInstallationRequest{
		Caller:         outsiderPrincipal,
		OrgId:          otherOrg.ID.String(),
		InstallationId: 77001,
		State:          otherStart.GetState(),
	}); status.Code(err) != codes.AlreadyExists {
		t.Fatalf("expected AlreadyExists when linking installation to second org, got %v", err)
	}

	// 3. ListGitHubInstallations allows member (service:read / org:read) and denies outsider
	if _, err := srv.ListGitHubInstallations(ctx, &authv1.ListGitHubInstallationsRequest{
		Caller: outsiderPrincipal,
		OrgId:  org.ID.String(),
	}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("expected PermissionDenied for outsider ListGitHubInstallations, got %v", err)
	}
	listInstResp, err := srv.ListGitHubInstallations(ctx, &authv1.ListGitHubInstallationsRequest{
		Caller: memberPrincipal,
		OrgId:  org.ID.String(),
	})
	if err != nil || len(listInstResp.GetInstallations()) != 1 {
		t.Fatalf("ListGitHubInstallations: err=%v, resp=%+v", err, listInstResp)
	}

	// 4. Repository Explorer (repositories, branches, directories) allowed for member (service:read), scoped to org installation
	if _, err := srv.ListGitHubRepositories(ctx, &authv1.ListGitHubRepositoriesRequest{
		Caller:         outsiderPrincipal,
		OrgId:          otherOrg.ID.String(),
		InstallationId: 77001, // belongs to `org`, not `otherOrg`
	}); status.Code(err) != codes.NotFound {
		t.Fatalf("expected NotFound when querying installation not linked to org, got %v", err)
	}

	reposResp, err := srv.ListGitHubRepositories(ctx, &authv1.ListGitHubRepositoriesRequest{
		Caller:         memberPrincipal,
		OrgId:          org.ID.String(),
		InstallationId: 77001,
	})
	if err != nil || len(reposResp.GetRepositories()) != 1 || reposResp.GetRepositories()[0].GetFullName() != "acme-gh/monorepo" {
		t.Fatalf("ListGitHubRepositories: err=%v, resp=%+v", err, reposResp)
	}

	branchesResp, err := srv.ListGitHubBranches(ctx, &authv1.ListGitHubBranchesRequest{
		Caller:         memberPrincipal,
		OrgId:          org.ID.String(),
		InstallationId: 77001,
		Owner:          "acme-gh",
		Repo:           "monorepo",
	})
	if err != nil || len(branchesResp.GetBranches()) != 1 || branchesResp.GetBranches()[0].GetName() != "main" {
		t.Fatalf("ListGitHubBranches: err=%v, resp=%+v", err, branchesResp)
	}

	dirsResp, err := srv.ListGitHubDirectories(ctx, &authv1.ListGitHubDirectoriesRequest{
		Caller:         memberPrincipal,
		OrgId:          org.ID.String(),
		InstallationId: 77001,
		Owner:          "acme-gh",
		Repo:           "monorepo",
		Ref:            "main",
	})
	if err != nil {
		t.Fatalf("ListGitHubDirectories: %v", err)
	}
	wantDirs := []string{"/", "/apps", "/apps/api", "/apps/web"}
	if len(dirsResp.GetDirectories()) != len(wantDirs) {
		t.Fatalf("expected directories %v, got %v", wantDirs, dirsResp.GetDirectories())
	}

	// 5. DisconnectGitHubInstallation requires org:update and emits audit event
	if _, err := srv.DisconnectGitHubInstallation(ctx, &authv1.DisconnectGitHubInstallationRequest{
		Caller:         memberPrincipal,
		OrgId:          org.ID.String(),
		InstallationId: 77001,
	}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("expected PermissionDenied for member DisconnectGitHubInstallation, got %v", err)
	}

	if _, err := srv.DisconnectGitHubInstallation(ctx, &authv1.DisconnectGitHubInstallationRequest{
		Caller:         ownerPrincipal,
		OrgId:          org.ID.String(),
		InstallationId: 77001,
	}); err != nil {
		t.Fatalf("DisconnectGitHubInstallation: %v", err)
	}

	events, _ := auditRepo.ListByOrg(ctx, org.ID, "", 10, 0)
	var actions []string
	for _, ev := range events {
		actions = append(actions, ev.Action)
	}
	if len(actions) < 2 || actions[0] != "github.installation_disconnected" || actions[1] != "github.installation_connected" {
		t.Fatalf("expected audit events [github.installation_disconnected github.installation_connected], got %v", actions)
	}
}
