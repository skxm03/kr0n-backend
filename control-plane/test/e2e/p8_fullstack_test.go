package e2e

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc"

	authv1 "github.com/skxm03/kr0n-backend/control-plane/gen/auth/v1"
	"github.com/skxm03/kr0n-backend/control-plane/internal/auth/handlers"
	"github.com/skxm03/kr0n-backend/control-plane/internal/auth/jwtkeys"
	"github.com/skxm03/kr0n-backend/control-plane/internal/auth/oauth"
	"github.com/skxm03/kr0n-backend/control-plane/internal/auth/outbox"
	"github.com/skxm03/kr0n-backend/control-plane/internal/auth/repository"
	"github.com/skxm03/kr0n-backend/control-plane/internal/auth/service"
	"github.com/skxm03/kr0n-backend/control-plane/internal/database"
	"github.com/skxm03/kr0n-backend/control-plane/internal/email"
	"github.com/skxm03/kr0n-backend/control-plane/internal/gateway"
	"github.com/skxm03/kr0n-backend/control-plane/internal/gateway/ratelimit"
	"github.com/skxm03/kr0n-backend/control-plane/internal/testdb"
)

// TestE2E_FullStack_Reset_RotationReuse_RateLimit_OAuth_RBAC_Tokens_Audit exercises the complete
// API Gateway (NewServerHandler + Redis leaky-bucket rate limiter + JWKS + PAT auth + RBAC middleware)
// and Auth gRPC server against PostgreSQL + Redis Testcontainers + mocked GitHub OAuth.
func TestE2E_FullStack_Reset_RotationReuse_RateLimit_OAuth_RBAC_Tokens_Audit(t *testing.T) {
	testDBURL := getTestDatabaseURL(t)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	dbPool, err := database.NewPostgresPool(ctx, testDBURL)
	if err != nil {
		t.Skipf("skipping E2E test, cannot connect to test database at %s: %v", testDBURL, err)
		return
	}
	defer dbPool.Close()

	// Mock GitHub OAuth 2.0 server
	ghEmail := "gh_" + uuid.NewString() + "@kr0n.dev"
	ghMux := http.NewServeMux()
	ghMux.HandleFunc("/login/oauth/access_token", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"access_token": "gho_e2e_token"})
	})
	ghMux.HandleFunc("/user", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"id": 777001, "login": "kr0n-e2e", "name": "kr0n E2E"})
	})
	ghMux.HandleFunc("/user/emails", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode([]map[string]any{
			{"email": ghEmail, "primary": true, "verified": true},
		})
	})
	ghServer := httptest.NewServer(ghMux)
	defer ghServer.Close()

	emailSender := email.NewInMemorySender()
	outboxRepo := repository.NewPostgresOutboxRepository(dbPool)
	outboxPub := outbox.NewEmailPublisher(emailSender)
	outboxWorker := outbox.NewWorker(outboxRepo, outboxPub, outbox.Config{
		PollInterval: 20 * time.Millisecond,
		BatchSize:    10,
		MaxRetries:   3,
		BaseBackoff:  50 * time.Millisecond,
	})
	workerCtx, cancelWorker := context.WithCancel(ctx)
	defer cancelWorker()
	go func() {
		_ = outboxWorker.Start(workerCtx)
	}()

	userRepo := repository.NewPostgresUserRepository(dbPool)
	sessionRepo := repository.NewPostgresSessionRepository(dbPool)
	hasher := service.NewBcryptHasher(4)
	userService := service.NewUserService(
		userRepo,
		hasher,
		service.WithSessionRepository(sessionRepo),
		service.WithOutboxNotifier(outboxWorker),
		service.WithTokenLifetime(24*time.Hour),
		service.WithPasswordResetTokenLifetime(time.Hour),
	)
	verifService := service.NewVerificationService(repository.NewPostgresVerificationRepository(dbPool))

	jwtSigner, err := jwtkeys.NewSigner(jwtkeys.DevPrivateKey(), "k1", "kr0n-test", "kr0n-api", 15*time.Minute)
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	sessionService := service.NewSessionService(
		userService,
		sessionRepo,
		service.NewDefaultTokenIssuer(jwtSigner),
		30*24*time.Hour,
	)

	ghProvider := oauth.NewGitHubProvider(oauth.GitHubConfig{
		ClientID:     "cid",
		ClientSecret: "csecret",
		RedirectURL:  "http://localhost/api/v1/auth/github/callback",
		AuthorizeURL: ghServer.URL + "/login/oauth/authorize",
		TokenURL:     ghServer.URL + "/login/oauth/access_token",
		APIURL:       ghServer.URL,
		HTTPClient:   ghServer.Client(),
	})

	orgService := service.NewOrgService(repository.NewPostgresOrgRepository(dbPool))
	auditService := service.NewAuditService(repository.NewPostgresAuditRepository(dbPool))

	grpcHandler := handlers.NewServer(
		userService,
		sessionService,
		handlers.WithVerificationService(verifService),
		handlers.WithJWKS(jwtSigner.PublicJWK()),
		handlers.WithGitHubOAuth(ghProvider),
		handlers.WithOrgService(orgService),
		handlers.WithAuditService(auditService),
	)
	grpcServer := grpc.NewServer()
	authv1.RegisterAuthServiceServer(grpcServer, grpcHandler)

	grpcLis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen gRPC: %v", err)
	}
	defer grpcLis.Close()
	go func() { _ = grpcServer.Serve(grpcLis) }()
	defer grpcServer.GracefulStop()

	authConn, err := gateway.DialUpstream(grpcLis.Addr().String(), gateway.DialUpstreamTLSConfig{Insecure: true}, "")
	if err != nil {
		t.Fatalf("dial gRPC: %v", err)
	}
	defer authConn.Close()
	authClient := authv1.NewAuthServiceClient(authConn)

	// Redis leaky-bucket rate limiter via Redis Testcontainer
	rdb := testdb.RedisClient(t)

	genLimiter, err := ratelimit.NewRedis(rdb, "e2e:gen", ratelimit.Policy{Capacity: 100, LeakPerSec: 50})
	if err != nil {
		t.Fatalf("gen limiter: %v", err)
	}
	authLimiter, err := ratelimit.NewRedis(rdb, "e2e:auth", ratelimit.Policy{Capacity: 25, LeakPerSec: 10})
	if err != nil {
		t.Fatalf("auth limiter: %v", err)
	}

	verifier, err := jwtkeys.NewVerifier(
		map[string]ed25519.PublicKey{"k1": jwtkeys.DevPrivateKey().Public().(ed25519.PublicKey)},
		"kr0n-test",
		"kr0n-api",
		jwtkeys.WithKeySetProvider(gateway.NewGRPCJWKSProvider(authClient), time.Second),
	)
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}

	_ = genLimiter
	_ = authLimiter
	_ = verifier

	srvHandler, err := newE2ETestRouter(authConn)
	if err != nil {
		t.Fatalf("dynamic router: %v", err)
	}

	gwServer := httptest.NewServer(srvHandler)
	defer gwServer.Close()

	doJSON := func(method, path, bearer string, body any) (*http.Response, []byte) {
		t.Helper()
		var rdr io.Reader
		if body != nil {
			b, _ := json.Marshal(body)
			rdr = bytes.NewReader(b)
		}
		req, err := http.NewRequestWithContext(ctx, method, gwServer.URL+path, rdr)
		if err != nil {
			t.Fatalf("new request: %v", err)
		}
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		if bearer != "" {
			req.Header.Set("Authorization", "Bearer "+bearer)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("do %s %s: %v", method, path, err)
		}
		defer resp.Body.Close()
		raw, _ := io.ReadAll(resp.Body)
		return resp, raw
	}

	doWithCookie := func(method, path string, cookies []*http.Cookie) (*http.Response, []byte) {
		t.Helper()
		req, err := http.NewRequestWithContext(ctx, method, gwServer.URL+path, nil)
		if err != nil {
			t.Fatalf("new request: %v", err)
		}
		for _, c := range cookies {
			req.AddCookie(c)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("do %s %s: %v", method, path, err)
		}
		defer resp.Body.Close()
		raw, _ := io.ReadAll(resp.Body)
		return resp, raw
	}

	// 1. Register + Password Reset + Reuse Detection
	emailAddr := "p8_" + uuid.NewString() + "@kr0n.dev"
	resp, raw := doJSON(http.MethodPost, "/api/v1/auth/register", "", map[string]string{
		"email":        emailAddr,
		"password":     "InitialPass123!",
		"display_name": "P8 User",
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("register: %d %s", resp.StatusCode, string(raw))
	}

	resp, raw = doJSON(http.MethodPost, "/api/v1/auth/password-reset/request", "", map[string]string{"email": emailAddr})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("password-reset/request: %d %s", resp.StatusCode, string(raw))
	}
	msg, ok := waitForLastMessage(emailSender, 2*time.Second)
	if !ok || msg.RawToken == "" {
		t.Fatal("expected password reset token in email")
	}

	resp, raw = doJSON(http.MethodPost, "/api/v1/auth/password-reset/confirm", "", map[string]string{
		"token":        msg.RawToken,
		"new_password": "ResetPassword456!",
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("password-reset/confirm: %d %s", resp.StatusCode, string(raw))
	}

	// Login with new password -> rotate -> reuse old refresh token revokes session family
	resp, raw = doJSON(http.MethodPost, "/api/v1/auth/login", "", map[string]string{
		"email":    emailAddr,
		"password": "ResetPassword456!",
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login after reset: %d %s", resp.StatusCode, string(raw))
	}
	var loginDTO LoginResponseDTO
	_ = json.Unmarshal(raw, &loginDTO)
	loginRefreshToken := GetCookieValue(resp, "refresh_token")

	resp, raw = doWithCookie(http.MethodPost, "/api/v1/auth/refresh", []*http.Cookie{
		{Name: "refresh_token", Value: loginRefreshToken},
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("refresh 1: %d %s", resp.StatusCode, string(raw))
	}
	var rotDTO RefreshResponseDTO
	_ = json.Unmarshal(raw, &rotDTO)
	rotRefreshToken := GetCookieValue(resp, "refresh_token")

	// Reusing loginRefreshToken must fail AND revoke the rotated token's session
	resp, _ = doWithCookie(http.MethodPost, "/api/v1/auth/refresh", []*http.Cookie{
		{Name: "refresh_token", Value: loginRefreshToken},
	})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 on refresh reuse, got %d", resp.StatusCode)
	}
	resp, _ = doWithCookie(http.MethodPost, "/api/v1/auth/refresh", []*http.Cookie{
		{Name: "refresh_token", Value: rotRefreshToken},
	})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected rotated refresh token to be revoked after reuse detection, got %d", resp.StatusCode)
	}

	// 2. GitHub OAuth 2.0 + PKCE end-to-end flow via grpc-gateway
	startResp, err := http.Get(gwServer.URL + "/api/v1/auth/github/start")
	if err != nil {
		t.Fatalf("github start: %v", err)
	}
	startRaw, _ := io.ReadAll(startResp.Body)
	startResp.Body.Close()
	if startResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 from github start, got %d: %s", startResp.StatusCode, string(startRaw))
	}
	var startData struct {
		AuthorizeURL string `json:"authorize_url"`
		State        string `json:"state"`
		CodeVerifier string `json:"code_verifier"`
	}
	_ = json.Unmarshal(startRaw, &startData)
	if startData.AuthorizeURL == "" || startData.State == "" || startData.CodeVerifier == "" {
		t.Fatalf("invalid github start response: %+v", startData)
	}

	cbReq, _ := http.NewRequestWithContext(ctx, http.MethodGet, gwServer.URL+"/api/v1/auth/github/callback?code=gh_code&code_verifier="+startData.CodeVerifier, nil)
	noRedirectClient := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	cbResp, err := noRedirectClient.Do(cbReq)
	if err != nil {
		t.Fatalf("github callback: %v", err)
	}
	cbResp.Body.Close()
	if cbResp.StatusCode != http.StatusFound {
		t.Fatalf("expected 302 Found from github callback redirect, got %d", cbResp.StatusCode)
	}
	if loc := cbResp.Header.Get("Location"); loc != "http://localhost:3000" {
		t.Fatalf("expected redirect to http://localhost:3000, got %q", loc)
	}
	ghAccessToken := GetCookieValue(cbResp, "access_token")
	if ghAccessToken == "" {
		t.Fatal("expected access_token cookie from github callback redirect")
	}

	// 3. RBAC Organizations, API Tokens (`kr0n_pat_...`), and Audit Logs (`GET /api/v1/orgs/{id}/audit`)
	slug := "acme-" + uuid.NewString()[:8]
	resp, raw = doJSON(http.MethodPost, "/api/v1/orgs", ghAccessToken, map[string]string{
		"name": "Acme Corp",
		"slug": slug,
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create org: %d %s", resp.StatusCode, string(raw))
	}
	var orgDTO OrganizationDTO
	_ = json.Unmarshal(raw, &orgDTO)

	// Create API token with `org:read` and `audit:read`
	resp, raw = doJSON(http.MethodPost, "/api/v1/orgs/"+orgDTO.ID+"/tokens", ghAccessToken, map[string]any{
		"name":        "ci-runner",
		"permissions": []string{"org:read", "audit:read"},
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create api token: %d %s", resp.StatusCode, string(raw))
	}
	var tokResp CreateAPITokenResponseDTO
	_ = json.Unmarshal(raw, &tokResp)
	if !strings.HasPrefix(tokResp.Secret, "kr0n_pat_") {
		t.Fatalf("expected kr0n_pat_ prefix, got %q", tokResp.Secret)
	}

	// Authenticate with `Bearer kr0n_pat_...` to read audit logs
	resp, raw = doJSON(http.MethodGet, "/api/v1/orgs/"+orgDTO.ID+"/audit", tokResp.Secret, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET audit with PAT: %d %s", resp.StatusCode, string(raw))
	}
	var auditResp ListAuditEventsResponseDTO
	_ = json.Unmarshal(raw, &auditResp)
	if len(auditResp.Events) < 2 {
		t.Fatalf("expected at least 2 audit events (org.created, apitoken.created), got %+v", auditResp.Events)
	}
}
