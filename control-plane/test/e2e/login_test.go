package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	authv1 "github.com/skxm03/kr0n-backend/control-plane/gen/auth/v1"
	"github.com/skxm03/kr0n-backend/control-plane/internal/auth/session"
	authgrpc "github.com/skxm03/kr0n-backend/control-plane/internal/auth/transport/grpc"
	"github.com/skxm03/kr0n-backend/control-plane/internal/auth/user"
	"github.com/skxm03/kr0n-backend/control-plane/internal/database"
	"github.com/skxm03/kr0n-backend/control-plane/internal/gateway"
)

func startE2ECluster(t *testing.T, ctx context.Context) (*pgxpool.Pool, string, func()) {
	t.Helper()
	testDBURL := getTestDatabaseURL()

	dbPool, err := database.NewPostgresPool(ctx, testDBURL)
	if err != nil {
		t.Skipf("skipping E2E test, cannot connect to test database at %s: %v", testDBURL, err)
		return nil, "", func() {}
	}

	userRepo := user.NewPostgresRepository(dbPool)
	hasher := user.NewBcryptHasher(12)
	userService := user.NewService(userRepo, hasher)

	jwtSigner, err := session.NewJWTSigner([]byte("test_jwt_secret_key_at_least_32_bytes_long!"), "kr0n-test", 15*time.Minute)
	if err != nil {
		t.Fatalf("failed to create jwt signer: %v", err)
	}
	tokenIssuer := session.NewDefaultTokenIssuer(jwtSigner)
	sessionRepo := session.NewPostgresRepository(dbPool)
	sessionService := session.NewService(userService, sessionRepo, tokenIssuer, 30*24*time.Hour)

	grpcHandler := authgrpc.NewServer(userService, sessionService)

	grpcServer := grpc.NewServer()
	authv1.RegisterAuthServiceServer(grpcServer, grpcHandler)

	grpcListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen on gRPC loopback: %v", err)
	}

	go func() {
		_ = grpcServer.Serve(grpcListener)
	}()

	authGRPCAddr := grpcListener.Addr().String()

	authConn, err := grpc.NewClient(authGRPCAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("failed to dial auth gRPC: %v", err)
	}

	authClient := authv1.NewAuthServiceClient(authConn)
	gwHandler := gateway.NewHandler(authClient)
	gwRouter := gateway.NewRouter(gwHandler)

	httpListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen on HTTP loopback: %v", err)
	}

	httpServer := &http.Server{
		Handler: gwRouter,
	}
	go func() {
		_ = httpServer.Serve(httpListener)
	}()

	gatewayBaseURL := "http://" + httpListener.Addr().String()

	cleanup := func() {
		_ = httpServer.Close()
		_ = httpListener.Close()
		_ = authConn.Close()
		grpcServer.GracefulStop()
		_ = grpcListener.Close()
		dbPool.Close()
	}

	return dbPool, gatewayBaseURL, cleanup
}

func TestE2E_Login_Slice(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	dbPool, baseURL, cleanup := startE2ECluster(t, ctx)
	if dbPool == nil {
		return
	}
	defer cleanup()

	registerURL := baseURL + "/api/v1/auth/register"
	loginURL := baseURL + "/api/v1/auth/login"

	uniqueID := uuid.New().String()
	email := "e2e_login_" + uniqueID + "@kr0n.dev"
	password := "SecureLoginPass123!"
	displayName := "E2E Login User"

	// 1. REGISTER USER
	regBody, _ := json.Marshal(map[string]string{
		"email":        email,
		"password":     password,
		"display_name": displayName,
	})
	regReq, _ := http.NewRequestWithContext(ctx, http.MethodPost, registerURL, bytes.NewReader(regBody))
	regReq.Header.Set("Content-Type", "application/json")

	regResp, err := http.DefaultClient.Do(regReq)
	if err != nil {
		t.Fatalf("register request failed: %v", err)
	}
	defer regResp.Body.Close()

	if regResp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(regResp.Body)
		t.Fatalf("expected 201 Created on register, got %d: %s", regResp.StatusCode, string(b))
	}

	var regData gateway.RegisterResponseDTO
	_ = json.NewDecoder(regResp.Body).Decode(&regData)
	userID, err := uuid.Parse(regData.UserID)
	if err != nil {
		t.Fatalf("failed to parse returned user ID: %v", err)
	}

	// 2. LOGIN WITH CORRECT CREDENTIALS (canonicalization verification: mixed case + whitespace)
	t.Run("login with correct credentials succeeds and creates session", func(t *testing.T) {
		loginBody, _ := json.Marshal(map[string]string{
			"email":    "  " + email + "  ",
			"password": password,
		})
		loginReq, _ := http.NewRequestWithContext(ctx, http.MethodPost, loginURL, bytes.NewReader(loginBody))
		loginReq.Header.Set("Content-Type", "application/json")
		loginReq.Header.Set("User-Agent", "kr0n-e2e-agent/1.0")

		resp, err := http.DefaultClient.Do(loginReq)
		if err != nil {
			t.Fatalf("login request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			b, _ := io.ReadAll(resp.Body)
			t.Fatalf("expected 200 OK, got %d: %s", resp.StatusCode, string(b))
		}

		var loginResult gateway.LoginResponseDTO
		if err := json.NewDecoder(resp.Body).Decode(&loginResult); err != nil {
			t.Fatalf("decode login response failed: %v", err)
		}

		if loginResult.AccessToken == "" {
			t.Fatal("expected non-empty access_token")
		}
		if loginResult.RefreshToken == "" {
			t.Fatal("expected non-empty refresh_token")
		}
		if loginResult.TokenType != "Bearer" {
			t.Fatalf("expected token_type Bearer, got %s", loginResult.TokenType)
		}
		if loginResult.ExpiresIn != 900 {
			t.Fatalf("expected 900s expires_in, got %d", loginResult.ExpiresIn)
		}
		if loginResult.User.ID != userID.String() {
			t.Fatalf("expected user id %s, got %s", userID.String(), loginResult.User.ID)
		}
		if loginResult.User.Email != email {
			t.Fatalf("expected user email %s, got %s", email, loginResult.User.Email)
		}

		// 3. VERIFY SESSION IN POSTGRESQL
		var (
			storedHash  string
			storedUA    *string
			storedIP    *string
			storedRevok *time.Time
		)
		err = dbPool.QueryRow(ctx, `
			SELECT token_hash, user_agent, host(ip_address), revoked_at
			FROM sessions WHERE user_id = $1
		`, userID).Scan(&storedHash, &storedUA, &storedIP, &storedRevok)
		if err != nil {
			t.Fatalf("failed to query sessions table: %v", err)
		}

		// 4. Verify raw refresh token NEVER stored
		if storedHash == loginResult.RefreshToken {
			t.Fatal("SECURITY VIOLATION: raw refresh token is stored in database!")
		}

		// 5. Verify returned refresh token corresponds to stored hash
		if !session.VerifyRefreshToken(loginResult.RefreshToken, storedHash) {
			t.Fatal("stored hash does not match returned refresh token")
		}

		if storedUA == nil || *storedUA != "kr0n-e2e-agent/1.0" {
			t.Fatalf("expected User-Agent kr0n-e2e-agent/1.0, got %v", storedUA)
		}
		if storedRevok != nil {
			t.Fatal("expected active session revoked_at to be NULL")
		}
	})

	// 6. LOGIN WITH INCORRECT PASSWORD
	t.Run("login with incorrect password fails and creates no new session", func(t *testing.T) {
		var sessionCountBefore int
		_ = dbPool.QueryRow(ctx, "SELECT count(*) FROM sessions WHERE user_id = $1", userID).Scan(&sessionCountBefore)

		loginBody, _ := json.Marshal(map[string]string{
			"email":    email,
			"password": "WrongPassword999!",
		})
		loginReq, _ := http.NewRequestWithContext(ctx, http.MethodPost, loginURL, bytes.NewReader(loginBody))
		loginReq.Header.Set("Content-Type", "application/json")

		resp, err := http.DefaultClient.Do(loginReq)
		if err != nil {
			t.Fatalf("login request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("expected 401 Unauthorized, got %d", resp.StatusCode)
		}

		var errResp gateway.ErrorResponseDTO
		_ = json.NewDecoder(resp.Body).Decode(&errResp)
		if errResp.Error != "invalid email or password" {
			t.Fatalf("expected 'invalid email or password', got %s", errResp.Error)
		}

		var sessionCountAfter int
		_ = dbPool.QueryRow(ctx, "SELECT count(*) FROM sessions WHERE user_id = $1", userID).Scan(&sessionCountAfter)
		if sessionCountAfter != sessionCountBefore {
			t.Fatalf("expected no new sessions created, count was %d, now %d", sessionCountBefore, sessionCountAfter)
		}
	})

	// 7. LOGIN WITH UNKNOWN EMAIL PRODUCES SAME EXTERNAL ERROR
	t.Run("login with unknown email returns identical 401 error", func(t *testing.T) {
		loginBody, _ := json.Marshal(map[string]string{
			"email":    "nonexistent_" + uuid.New().String() + "@kr0n.dev",
			"password": "AnyPassword123!",
		})
		loginReq, _ := http.NewRequestWithContext(ctx, http.MethodPost, loginURL, bytes.NewReader(loginBody))
		loginReq.Header.Set("Content-Type", "application/json")

		resp, err := http.DefaultClient.Do(loginReq)
		if err != nil {
			t.Fatalf("login request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("expected 401 Unauthorized, got %d", resp.StatusCode)
		}

		var errResp gateway.ErrorResponseDTO
		_ = json.NewDecoder(resp.Body).Decode(&errResp)
		if errResp.Error != "invalid email or password" {
			t.Fatalf("expected 'invalid email or password', got %s", errResp.Error)
		}
		if errResp.Code != "UNAUTHORIZED" {
			t.Fatalf("expected code UNAUTHORIZED, got %s", errResp.Code)
		}
	})

	// 8. INACTIVE/DEACTIVATED USER CANNOT LOGIN
	t.Run("inactive user cannot login", func(t *testing.T) {
		inactiveEmail := "inactive_" + uuid.New().String() + "@kr0n.dev"
		inactivePass := "Password12345!"

		// Register
		regBody, _ := json.Marshal(map[string]string{
			"email":        inactiveEmail,
			"password":     inactivePass,
			"display_name": "Inactive User",
		})
		regReq, _ := http.NewRequestWithContext(ctx, http.MethodPost, registerURL, bytes.NewReader(regBody))
		regReq.Header.Set("Content-Type", "application/json")
		regResp, _ := http.DefaultClient.Do(regReq)
		regResp.Body.Close()

		// Update status to suspended in database
		_, err := dbPool.Exec(ctx, "UPDATE users SET status = 'suspended' WHERE email = $1", inactiveEmail)
		if err != nil {
			t.Fatalf("update status failed: %v", err)
		}

		// Attempt login
		loginBody, _ := json.Marshal(map[string]string{
			"email":    inactiveEmail,
			"password": inactivePass,
		})
		loginReq, _ := http.NewRequestWithContext(ctx, http.MethodPost, loginURL, bytes.NewReader(loginBody))
		loginReq.Header.Set("Content-Type", "application/json")

		resp, err := http.DefaultClient.Do(loginReq)
		if err != nil {
			t.Fatalf("login request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("expected 403 Forbidden for suspended user, got %d", resp.StatusCode)
		}
	})
}
