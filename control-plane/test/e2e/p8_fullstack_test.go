package e2e

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	authv1 "github.com/skxm03/kr0n-backend/control-plane/gen/auth/v1"
	"github.com/skxm03/kr0n-backend/control-plane/internal/auth/audit"
	"github.com/skxm03/kr0n-backend/control-plane/internal/auth/jwtkeys"
	"github.com/skxm03/kr0n-backend/control-plane/internal/auth/oauth"
	"github.com/skxm03/kr0n-backend/control-plane/internal/auth/org"
	"github.com/skxm03/kr0n-backend/control-plane/internal/auth/session"
	authgrpc "github.com/skxm03/kr0n-backend/control-plane/internal/auth/transport/grpc"
	"github.com/skxm03/kr0n-backend/control-plane/internal/auth/user"
	"github.com/skxm03/kr0n-backend/control-plane/internal/auth/verification"
	"github.com/skxm03/kr0n-backend/control-plane/internal/database"
	"github.com/skxm03/kr0n-backend/control-plane/internal/email"
	"github.com/skxm03/kr0n-backend/control-plane/internal/gateway"
	"github.com/skxm03/kr0n-backend/control-plane/internal/ratelimit"
)

// TestE2E_FullStack_Reset_RotationReuse_RateLimit_OAuth_RBAC_Tokens_Audit exercises the complete
// API Gateway (NewServerHandler + Redis leaky-bucket rate limiter + JWKS + PAT auth + RBAC middleware)
// and Auth gRPC server against PostgreSQL + miniredis + mocked GitHub OAuth.
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
	userRepo := user.NewPostgresRepository(dbPool)
	hasher := user.NewBcryptHasher(4)
	userService := user.NewService(
		userRepo,
		hasher,
		user.WithEmailSender(emailSender),
		user.WithTokenLifetime(24*time.Hour),
		user.WithPasswordResetTokenLifetime(time.Hour),
	)
	verifService := verification.NewService(verification.NewPostgresRepository(dbPool))

	jwtSigner, err := jwtkeys.NewSigner(jwtkeys.DevPrivateKey(), "k1", "kr0n-test", "kr0n-api", 15*time.Minute)
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	sessionService := session.NewService(
		userService,
		session.NewPostgresRepository(dbPool),
		session.NewDefaultTokenIssuer(jwtSigner),
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

	orgService := org.NewService(org.NewPostgresRepository(dbPool))
	auditService := audit.NewService(audit.NewPostgresRepository(dbPool))

	grpcHandler := authgrpc.NewServer(
		userService,
		sessionService,
		authgrpc.WithVerificationService(verifService),
		authgrpc.WithJWKS(jwtSigner.PublicJWK()),
		authgrpc.WithGitHubOAuth(ghProvider),
		authgrpc.WithOrgService(orgService),
		authgrpc.WithAuditService(auditService),
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

	authConn, err := grpc.NewClient(grpcLis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial gRPC: %v", err)
	}
	defer authConn.Close()
	authClient := authv1.NewAuthServiceClient(authConn)

	// Redis leaky-bucket rate limiter via miniredis
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer rdb.Close()

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

	srvHandler := gateway.NewServerHandler(gateway.NewHandler(authClient), gateway.Options{
		Log:            slog.New(slog.NewTextHandler(io.Discard, nil)),
		Verifier:       verifier,
		GeneralLimiter: genLimiter,
		AuthLimiter:    authLimiter,
	})

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
	msg, ok := emailSender.LastMessage()
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
	var loginDTO gateway.LoginResponseDTO
	_ = json.Unmarshal(raw, &loginDTO)

	resp, raw = doJSON(http.MethodPost, "/api/v1/auth/refresh", "", map[string]string{
		"refresh_token": loginDTO.RefreshToken,
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("refresh 1: %d %s", resp.StatusCode, string(raw))
	}
	var rotDTO gateway.RefreshResponseDTO
	_ = json.Unmarshal(raw, &rotDTO)

	// Reusing loginDTO.RefreshToken must fail AND revoke the rotated token's session
	resp, _ = doJSON(http.MethodPost, "/api/v1/auth/refresh", "", map[string]string{
		"refresh_token": loginDTO.RefreshToken,
	})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 on refresh reuse, got %d", resp.StatusCode)
	}
	resp, _ = doJSON(http.MethodPost, "/api/v1/auth/refresh", "", map[string]string{
		"refresh_token": rotDTO.RefreshToken,
	})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected rotated refresh token to be revoked after reuse detection, got %d", resp.StatusCode)
	}

	// 2. GitHub OAuth 2.0 + PKCE end-to-end flow
	noRedirectClient := &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	startResp, err := noRedirectClient.Get(gwServer.URL + "/api/v1/auth/github/start")
	if err != nil {
		t.Fatalf("github start: %v", err)
	}
	startResp.Body.Close()
	if startResp.StatusCode != http.StatusFound {
		t.Fatalf("expected 302 from github start, got %d", startResp.StatusCode)
	}
	var ghCookie *http.Cookie
	for _, c := range startResp.Cookies() {
		if c.Name == "kr0n_gh_oauth" {
			ghCookie = c
		}
	}
	if ghCookie == nil {
		t.Fatal("missing kr0n_gh_oauth cookie")
	}
	state, _, _ := strings.Cut(ghCookie.Value, ".")

	cbReq, _ := http.NewRequestWithContext(ctx, http.MethodGet, gwServer.URL+"/api/v1/auth/github/callback?code=gh_code&state="+state, nil)
	cbReq.AddCookie(ghCookie)
	cbResp, err := http.DefaultClient.Do(cbReq)
	if err != nil {
		t.Fatalf("github callback: %v", err)
	}
	cbRaw, _ := io.ReadAll(cbResp.Body)
	cbResp.Body.Close()
	if cbResp.StatusCode != http.StatusOK {
		t.Fatalf("github callback status: %d %s", cbResp.StatusCode, string(cbRaw))
	}
	var ghLogin gateway.LoginResponseDTO
	_ = json.Unmarshal(cbRaw, &ghLogin)
	if ghLogin.User.Email != ghEmail || ghLogin.AccessToken == "" {
		t.Fatalf("unexpected github login response: %+v", ghLogin)
	}

	// 3. RBAC Organizations, API Tokens (`kr0n_pat_...`), and Audit Logs (`GET /api/v1/orgs/{id}/audit`)
	slug := "acme-" + uuid.NewString()[:8]
	resp, raw = doJSON(http.MethodPost, "/api/v1/orgs", ghLogin.AccessToken, map[string]string{
		"name": "Acme Corp",
		"slug": slug,
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create org: %d %s", resp.StatusCode, string(raw))
	}
	var orgDTO gateway.OrganizationDTO
	_ = json.Unmarshal(raw, &orgDTO)

	// Create API token with `org:read` and `audit:read`
	resp, raw = doJSON(http.MethodPost, "/api/v1/orgs/"+orgDTO.ID+"/tokens", ghLogin.AccessToken, map[string]any{
		"name":        "ci-runner",
		"permissions": []string{"org:read", "audit:read"},
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create api token: %d %s", resp.StatusCode, string(raw))
	}
	var tokResp gateway.CreateAPITokenResponseDTO
	_ = json.Unmarshal(raw, &tokResp)
	if !strings.HasPrefix(tokResp.Secret, "kr0n_pat_") {
		t.Fatalf("expected kr0n_pat_ prefix, got %q", tokResp.Secret)
	}

	// Authenticate with `Bearer kr0n_pat_...` to read audit logs
	resp, raw = doJSON(http.MethodGet, "/api/v1/orgs/"+orgDTO.ID+"/audit", tokResp.Secret, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET audit with PAT: %d %s", resp.StatusCode, string(raw))
	}
	var auditResp gateway.ListAuditEventsResponseDTO
	_ = json.Unmarshal(raw, &auditResp)
	if len(auditResp.Events) < 2 {
		t.Fatalf("expected at least 2 audit events (org.created, apitoken.created), got %+v", auditResp.Events)
	}
}
