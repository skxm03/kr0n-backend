package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/skxm03/kr0n-backend/control-plane/internal/auth/jwtkeys"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	authv1 "github.com/skxm03/kr0n-backend/control-plane/gen/auth/v1"
	"github.com/skxm03/kr0n-backend/control-plane/internal/auth/handlers"
	"github.com/skxm03/kr0n-backend/control-plane/internal/auth/repository"
	"github.com/skxm03/kr0n-backend/control-plane/internal/auth/service"
	"github.com/skxm03/kr0n-backend/control-plane/internal/database"
	"github.com/skxm03/kr0n-backend/control-plane/internal/gateway"
	"github.com/skxm03/kr0n-backend/control-plane/internal/testdb"
)

// getTestDatabaseURL returns the isolated, fully migrated test database (TEST_DATABASE_URL only).
func getTestDatabaseURL(t *testing.T) string {
	t.Helper()
	return testdb.Migrated(t)
}

func TestE2E_UserRegistration(t *testing.T) {
	testDBURL := getTestDatabaseURL(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// 1. Connect to isolated test database
	dbPool, err := database.NewPostgresPool(ctx, testDBURL)
	if err != nil {
		t.Skipf("skipping E2E test, cannot connect to test database at %s: %v", testDBURL, err)
		return
	}
	defer dbPool.Close()

	// 2. Start Auth gRPC Service on dynamic loopback port
	userRepo := repository.NewPostgresUserRepository(dbPool)
	hasher := service.NewBcryptHasher(12)
	userService := service.NewUserService(userRepo, hasher)

	jwtSigner, err := jwtkeys.NewSigner(jwtkeys.DevPrivateKey(), "k1", "kr0n-test", "kr0n-api", 15*time.Minute)
	if err != nil {
		t.Fatalf("failed to create jwt signer: %v", err)
	}
	tokenIssuer := service.NewDefaultTokenIssuer(jwtSigner)
	sessionRepo := repository.NewPostgresSessionRepository(dbPool)
	sessionService := service.NewSessionService(userService, sessionRepo, tokenIssuer, 30*24*time.Hour)

	grpcHandler := handlers.NewServer(userService, sessionService)

	grpcServer := grpc.NewServer()
	authv1.RegisterAuthServiceServer(grpcServer, grpcHandler)

	grpcListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen on gRPC loopback: %v", err)
	}
	defer grpcListener.Close()

	go func() {
		_ = grpcServer.Serve(grpcListener)
	}()
	defer grpcServer.GracefulStop()

	authGRPCAddr := grpcListener.Addr().String()

	// 3. Start API Gateway on dynamic loopback port
	authConn, err := grpc.NewClient(authGRPCAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("failed to dial auth gRPC: %v", err)
	}
	defer authConn.Close()

	authClient := authv1.NewAuthServiceClient(authConn)
	gwHandler := gateway.NewHandler(authClient)
	gwRouter := gateway.NewServerHandler(gwHandler, gateway.Options{})

	httpListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen on HTTP loopback: %v", err)
	}
	defer httpListener.Close()

	httpServer := &http.Server{
		Handler: gwRouter,
	}
	go func() {
		_ = httpServer.Serve(httpListener)
	}()
	defer func() {
		_ = httpServer.Close()
	}()

	gatewayBaseURL := "http://" + httpListener.Addr().String()
	registerURL := gatewayBaseURL + "/api/v1/auth/register"

	uniqueID := uuid.New().String()
	email := "e2e_user_" + uniqueID + "@kr0n.dev"
	password := "SecureP@ssword123!"
	displayName := "E2E Test User"

	// 4. Test Scenario 1: Successful Registration
	t.Run("successful registration creates user and credentials", func(t *testing.T) {
		reqBody := map[string]string{
			"email":        "  " + strings.ToUpper(email) + "  ", // Test canonicalization end-to-end
			"password":     password,
			"display_name": displayName,
		}
		bodyBytes, _ := json.Marshal(reqBody)

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, registerURL, bytes.NewReader(bodyBytes))
		if err != nil {
			t.Fatalf("create request failed: %v", err)
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("HTTP request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusCreated {
			body, _ := io.ReadAll(resp.Body)
			t.Fatalf("expected status 201 Created, got %d: %s", resp.StatusCode, string(body))
		}

		var regResp gateway.RegisterResponseDTO
		if err := json.NewDecoder(resp.Body).Decode(&regResp); err != nil {
			t.Fatalf("decode response failed: %v", err)
		}

		if regResp.UserID == "" {
			t.Fatal("expected non-empty user_id in response")
		}
		parsedUUID, err := uuid.Parse(regResp.UserID)
		if err != nil {
			t.Fatalf("expected valid UUID for user_id, got %q: %v", regResp.UserID, err)
		}
		if regResp.Email != email {
			t.Fatalf("expected canonical email %q, got %q", email, regResp.Email)
		}
		if regResp.DisplayName != displayName {
			t.Fatalf("expected display name %q, got %q", displayName, regResp.DisplayName)
		}
		if regResp.Status != "active" {
			t.Fatalf("expected status 'active', got %q", regResp.Status)
		}
		if regResp.CreatedAt == "" {
			t.Fatal("expected non-empty created_at timestamp")
		}

		// Verify database records in PostgreSQL directly
		var (
			dbEmail       string
			dbDisplayName string
			dbStatus      string
		)
		err = dbPool.QueryRow(ctx, "SELECT email, display_name, status FROM users WHERE id = $1", parsedUUID).
			Scan(&dbEmail, &dbDisplayName, &dbStatus)
		if err != nil {
			t.Fatalf("failed to query users row from database: %v", err)
		}
		if dbEmail != email || dbDisplayName != displayName || dbStatus != "active" {
			t.Fatalf("unexpected database user row: email=%s, name=%s, status=%s", dbEmail, dbDisplayName, dbStatus)
		}

		var dbHash string
		err = dbPool.QueryRow(ctx, "SELECT password_hash FROM password_credentials WHERE user_id = $1", parsedUUID).
			Scan(&dbHash)
		if err != nil {
			t.Fatalf("failed to query password_credentials row from database: %v", err)
		}
		if err := bcrypt.CompareHashAndPassword([]byte(dbHash), []byte(password)); err != nil {
			t.Fatalf("stored password hash failed bcrypt verification: %v", err)
		}

		// Verify user starts unverified with email_verified_at = NULL
		var dbVerifiedAt *time.Time
		err = dbPool.QueryRow(ctx, "SELECT email_verified_at FROM users WHERE id = $1", parsedUUID).Scan(&dbVerifiedAt)
		if err != nil {
			t.Fatalf("failed to query email_verified_at: %v", err)
		}
		if dbVerifiedAt != nil {
			t.Fatal("expected newly registered user to have email_verified_at = NULL in database")
		}

		// Verify verification token record was created atomically in PostgreSQL
		var (
			tokenCount int
			tokenHash  string
		)
		err = dbPool.QueryRow(ctx, "SELECT count(*), COALESCE(max(token_hash), '') FROM email_verification_tokens WHERE user_id = $1", parsedUUID).
			Scan(&tokenCount, &tokenHash)
		if err != nil {
			t.Fatalf("failed to query email_verification_tokens: %v", err)
		}
		if tokenCount != 1 {
			t.Fatalf("expected exactly 1 verification token in database for newly registered user, got %d", tokenCount)
		}
		if tokenHash == "" {
			t.Fatal("expected non-empty token hash in database")
		}
	})

	// 5. Test Scenario 2: Duplicate Registration Returns 409 Conflict
	t.Run("duplicate registration returns 409 Conflict", func(t *testing.T) {
		reqBody := map[string]string{
			"email":        email,
			"password":     "AnotherPassword123!",
			"display_name": "Another Name",
		}
		bodyBytes, _ := json.Marshal(reqBody)

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, registerURL, bytes.NewReader(bodyBytes))
		if err != nil {
			t.Fatalf("create request failed: %v", err)
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("HTTP request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusConflict {
			body, _ := io.ReadAll(resp.Body)
			t.Fatalf("expected status 409 Conflict, got %d: %s", resp.StatusCode, string(body))
		}

		var errResp gateway.ErrorResponseDTO
		if err := json.NewDecoder(resp.Body).Decode(&errResp); err != nil {
			t.Fatalf("decode error response failed: %v", err)
		}

		if errResp.Code != "EMAIL_ALREADY_EXISTS" {
			t.Fatalf("expected code EMAIL_ALREADY_EXISTS, got %q", errResp.Code)
		}
	})

	// 6. Test Scenario 3: Validation Errors Return 400 Bad Request
	t.Run("short password returns 400 Bad Request", func(t *testing.T) {
		reqBody := map[string]string{
			"email":        "other_" + uuid.New().String() + "@kr0n.dev",
			"password":     "short",
			"display_name": "Valid Name",
		}
		bodyBytes, _ := json.Marshal(reqBody)

		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, registerURL, bytes.NewReader(bodyBytes))
		req.Header.Set("Content-Type", "application/json")

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("HTTP request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("expected status 400 Bad Request, got %d", resp.StatusCode)
		}
	})

	t.Run("password over 72 bytes returns 400 Bad Request", func(t *testing.T) {
		reqBody := map[string]string{
			"email":        "other_" + uuid.New().String() + "@kr0n.dev",
			"password":     strings.Repeat("p", 73),
			"display_name": "Valid Name",
		}
		bodyBytes, _ := json.Marshal(reqBody)

		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, registerURL, bytes.NewReader(bodyBytes))
		req.Header.Set("Content-Type", "application/json")

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("HTTP request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("expected status 400 Bad Request, got %d", resp.StatusCode)
		}
	})

	t.Run("invalid email returns 400 Bad Request", func(t *testing.T) {
		reqBody := map[string]string{
			"email":        "not-an-email",
			"password":     "ValidPassword123!",
			"display_name": "Valid Name",
		}
		bodyBytes, _ := json.Marshal(reqBody)

		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, registerURL, bytes.NewReader(bodyBytes))
		req.Header.Set("Content-Type", "application/json")

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("HTTP request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("expected status 400 Bad Request, got %d", resp.StatusCode)
		}
	})
}
