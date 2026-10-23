package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	authv1 "github.com/skxm03/kr0n-backend/control-plane/gen/auth/v1"
	"github.com/skxm03/kr0n-backend/control-plane/internal/auth/session"
	authgrpc "github.com/skxm03/kr0n-backend/control-plane/internal/auth/transport/grpc"
	"github.com/skxm03/kr0n-backend/control-plane/internal/auth/user"
	"github.com/skxm03/kr0n-backend/control-plane/internal/auth/verification"
	"github.com/skxm03/kr0n-backend/control-plane/internal/database"
	"github.com/skxm03/kr0n-backend/control-plane/internal/email"
	"github.com/skxm03/kr0n-backend/control-plane/internal/gateway"
)

func TestE2E_EmailVerification_Lifecycle(t *testing.T) {
	testDBURL := getTestDatabaseURL()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// 1. Connect to isolated test database
	dbPool, err := database.NewPostgresPool(ctx, testDBURL)
	if err != nil {
		t.Skipf("skipping E2E test, cannot connect to test database at %s: %v", testDBURL, err)
		return
	}
	defer dbPool.Close()

	// 2. Set up in-memory email sender to capture outgoing emails
	emailSender := email.NewInMemorySender()

	// 3. Start Auth gRPC Service on dynamic loopback port
	userRepo := user.NewPostgresRepository(dbPool)
	hasher := user.NewBcryptHasher(12)
	userService := user.NewService(
		userRepo,
		hasher,
		user.WithEmailSender(emailSender),
		user.WithTokenLifetime(24*time.Hour),
	)

	verifRepo := verification.NewPostgresRepository(dbPool)
	verifService := verification.NewService(verifRepo)

	jwtSigner, err := session.NewJWTSigner([]byte("test_jwt_secret_key_at_least_32_bytes_long!"), "kr0n-test", 15*time.Minute)
	if err != nil {
		t.Fatalf("failed to create jwt signer: %v", err)
	}
	tokenIssuer := session.NewDefaultTokenIssuer(jwtSigner)
	sessionRepo := session.NewPostgresRepository(dbPool)
	sessionService := session.NewService(userService, sessionRepo, tokenIssuer, 30*24*time.Hour)

	grpcHandler := authgrpc.NewServer(
		userService,
		sessionService,
		authgrpc.WithVerificationService(verifService),
	)

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

	// 4. Start API Gateway on dynamic loopback port
	authConn, err := grpc.NewClient(authGRPCAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("failed to dial auth gRPC: %v", err)
	}
	defer authConn.Close()

	authClient := authv1.NewAuthServiceClient(authConn)
	gwHandler := gateway.NewHandler(authClient)
	gwRouter := gateway.NewRouter(gwHandler)

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
	verifyEmailURL := gatewayBaseURL + "/api/v1/auth/verify-email"

	// -------------------------------------------------------------
	// Full Verification Lifecycle
	// -------------------------------------------------------------
	t.Run("complete verification lifecycle: register -> capture token -> verify -> reuse rejection", func(t *testing.T) {
		uniqueID := uuid.New().String()
		emailAddr := "e2e_verify_" + uniqueID + "@kr0n.dev"
		password := "SecureP@ssword123!"
		displayName := "Verification E2E User"

		// Step A: REGISTER via Gateway
		regBodyBytes, _ := json.Marshal(map[string]string{
			"email":        emailAddr,
			"password":     password,
			"display_name": displayName,
		})
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, registerURL, bytes.NewReader(regBodyBytes))
		req.Header.Set("Content-Type", "application/json")

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("registration request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusCreated {
			body, _ := io.ReadAll(resp.Body)
			t.Fatalf("expected 201 Created, got %d: %s", resp.StatusCode, string(body))
		}

		var regResp gateway.RegisterResponseDTO
		_ = json.NewDecoder(resp.Body).Decode(&regResp)
		parsedUserID, err := uuid.Parse(regResp.UserID)
		if err != nil {
			t.Fatalf("invalid user_id: %v", err)
		}

		// Step B: Confirm database state before verification
		// User must have email_verified_at = NULL
		var dbVerifiedAt *time.Time
		err = dbPool.QueryRow(ctx, "SELECT email_verified_at FROM users WHERE id = $1", parsedUserID).Scan(&dbVerifiedAt)
		if err != nil {
			t.Fatalf("query user email_verified_at failed: %v", err)
		}
		if dbVerifiedAt != nil {
			t.Fatal("expected email_verified_at to be NULL before verification")
		}

		// Step C: Capture verification email using test sender
		sentMsg, ok := emailSender.LastMessage()
		if !ok {
			t.Fatal("expected verification email to be captured by test sender")
		}
		if sentMsg.Recipient != emailAddr {
			t.Fatalf("expected recipient %q, got %q", emailAddr, sentMsg.Recipient)
		}
		rawToken := sentMsg.RawToken
		if rawToken == "" {
			t.Fatal("expected non-empty raw token in captured email")
		}

		// Confirm verification token hash exists in PostgreSQL
		tokenHash := verification.HashToken(rawToken)
		var (
			tokenID       uuid.UUID
			tokConsumedAt *time.Time
		)
		err = dbPool.QueryRow(ctx, "SELECT id, consumed_at FROM email_verification_tokens WHERE token_hash = $1", tokenHash).
			Scan(&tokenID, &tokConsumedAt)
		if err != nil {
			t.Fatalf("query token_hash in PostgreSQL failed: %v", err)
		}
		if tokConsumedAt != nil {
			t.Fatal("expected token to NOT be consumed yet")
		}

		// Confirm raw token is NOT in PostgreSQL
		var rawCount int
		_ = dbPool.QueryRow(ctx, "SELECT count(*) FROM email_verification_tokens WHERE token_hash = $1", rawToken).Scan(&rawCount)
		if rawCount != 0 {
			t.Fatal("CRITICAL SECURITY VIOLATION: raw verification token was found in PostgreSQL")
		}

		// Step D: POST /api/v1/auth/verify-email
		verifyBodyBytes, _ := json.Marshal(map[string]string{
			"token": rawToken,
		})
		vReq, _ := http.NewRequestWithContext(ctx, http.MethodPost, verifyEmailURL, bytes.NewReader(verifyBodyBytes))
		vReq.Header.Set("Content-Type", "application/json")

		vResp, err := http.DefaultClient.Do(vReq)
		if err != nil {
			t.Fatalf("verify email request failed: %v", err)
		}
		defer vResp.Body.Close()

		if vResp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(vResp.Body)
			t.Fatalf("expected 200 OK, got %d: %s", vResp.StatusCode, string(body))
		}

		var verifyResp gateway.VerifyEmailResponseDTO
		_ = json.NewDecoder(vResp.Body).Decode(&verifyResp)
		if verifyResp.Message != "email verified successfully" {
			t.Fatalf("expected message 'email verified successfully', got %q", verifyResp.Message)
		}

		// Step E: Confirm PostgreSQL state after verification
		// 1. users.email_verified_at is now populated
		err = dbPool.QueryRow(ctx, "SELECT email_verified_at FROM users WHERE id = $1", parsedUserID).Scan(&dbVerifiedAt)
		if err != nil {
			t.Fatalf("query user email_verified_at failed: %v", err)
		}
		if dbVerifiedAt == nil {
			t.Fatal("expected users.email_verified_at to be populated in PostgreSQL")
		}

		// 2. email_verification_tokens.consumed_at is now populated
		err = dbPool.QueryRow(ctx, "SELECT consumed_at FROM email_verification_tokens WHERE id = $1", tokenID).Scan(&tokConsumedAt)
		if err != nil {
			t.Fatalf("query consumed_at failed: %v", err)
		}
		if tokConsumedAt == nil {
			t.Fatal("expected email_verification_tokens.consumed_at to be populated in PostgreSQL")
		}

		// Step F: Attempt verification again with the same token -> must fail with 400 Bad Request
		reuseReq, _ := http.NewRequestWithContext(ctx, http.MethodPost, verifyEmailURL, bytes.NewReader(verifyBodyBytes))
		reuseReq.Header.Set("Content-Type", "application/json")

		reuseResp, err := http.DefaultClient.Do(reuseReq)
		if err != nil {
			t.Fatalf("reuse request failed: %v", err)
		}
		defer reuseResp.Body.Close()

		if reuseResp.StatusCode != http.StatusBadRequest {
			t.Fatalf("expected status 400 Bad Request on token reuse, got %d", reuseResp.StatusCode)
		}

		var errResp gateway.ErrorResponseDTO
		_ = json.NewDecoder(reuseResp.Body).Decode(&errResp)
		if errResp.Error != "invalid or expired verification token" {
			t.Fatalf("expected generic message 'invalid or expired verification token', got %q", errResp.Error)
		}
		if errResp.Code != "INVALID_ARGUMENT" {
			t.Fatalf("expected code INVALID_ARGUMENT, got %s", errResp.Code)
		}
	})

	// -------------------------------------------------------------
	// Invalid Token Rejection
	// -------------------------------------------------------------
	t.Run("invalid token returns 400 Bad Request", func(t *testing.T) {
		bodyBytes, _ := json.Marshal(map[string]string{
			"token": "completely_invalid_token_does_not_exist",
		})
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, verifyEmailURL, bytes.NewReader(bodyBytes))
		req.Header.Set("Content-Type", "application/json")

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("expected 400 Bad Request, got %d", resp.StatusCode)
		}

		var errResp gateway.ErrorResponseDTO
		_ = json.NewDecoder(resp.Body).Decode(&errResp)
		if errResp.Error != "invalid or expired verification token" {
			t.Fatalf("expected generic error message, got %q", errResp.Error)
		}
	})

	// -------------------------------------------------------------
	// Expired Token Rejection
	// -------------------------------------------------------------
	t.Run("expired token returns 400 Bad Request", func(t *testing.T) {
		// Create user and expired token directly in DB
		expiredUser, err := user.NewUser("expired_"+uuid.New().String()+"@kr0n.dev", "Expired User")
		if err != nil {
			t.Fatalf("NewUser failed: %v", err)
		}
		rawExpiredToken, _ := verification.GenerateToken()
		expiredHash := verification.HashToken(rawExpiredToken)
		now := time.Now().UTC()

		expiredTok := &verification.Token{
			ID:        uuid.New(),
			UserID:    expiredUser.ID,
			TokenHash: expiredHash,
			ExpiresAt: now.Add(-1 * time.Hour), // Expired 1 hour ago
			CreatedAt: now.Add(-2 * time.Hour),
		}

		if err := userRepo.CreateWithPasswordAndVerificationToken(ctx, expiredUser, "hash", expiredTok); err != nil {
			t.Fatalf("create user with expired token failed: %v", err)
		}

		// Attempt verification with expired token
		bodyBytes, _ := json.Marshal(map[string]string{
			"token": rawExpiredToken,
		})
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, verifyEmailURL, bytes.NewReader(bodyBytes))
		req.Header.Set("Content-Type", "application/json")

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("expected 400 Bad Request, got %d", resp.StatusCode)
		}

		var errResp gateway.ErrorResponseDTO
		_ = json.NewDecoder(resp.Body).Decode(&errResp)
		if errResp.Error != "invalid or expired verification token" {
			t.Fatalf("expected generic error message, got %q", errResp.Error)
		}

		// Ensure user remains unverified
		var verifiedAt *time.Time
		_ = dbPool.QueryRow(ctx, "SELECT email_verified_at FROM users WHERE id = $1", expiredUser.ID).Scan(&verifiedAt)
		if verifiedAt != nil {
			t.Fatal("expected expired user to remain unverified")
		}
	})

	// -------------------------------------------------------------
	// Concurrent Verification Requests Over HTTP
	// -------------------------------------------------------------
	t.Run("concurrent verification requests result in exactly one success", func(t *testing.T) {
		uniqueID := uuid.New().String()
		emailAddr := "concurrent_" + uniqueID + "@kr0n.dev"

		regBodyBytes, _ := json.Marshal(map[string]string{
			"email":        emailAddr,
			"password":     "SecureP@ssword123!",
			"display_name": "Concurrent User",
		})
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, registerURL, bytes.NewReader(regBodyBytes))
		req.Header.Set("Content-Type", "application/json")

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("registration failed: %v", err)
		}
		resp.Body.Close()

		sentMsg, ok := emailSender.LastMessage()
		if !ok {
			t.Fatal("expected email message")
		}
		rawToken := sentMsg.RawToken

		const concurrentRequests = 10
		var (
			successCount int64
			failureCount int64
			wg           sync.WaitGroup
		)
		wg.Add(concurrentRequests)

		for i := 0; i < concurrentRequests; i++ {
			go func() {
				defer wg.Done()
				bodyBytes, _ := json.Marshal(map[string]string{
					"token": rawToken,
				})
				cReq, _ := http.NewRequestWithContext(ctx, http.MethodPost, verifyEmailURL, bytes.NewReader(bodyBytes))
				cReq.Header.Set("Content-Type", "application/json")

				cResp, err := http.DefaultClient.Do(cReq)
				if err != nil {
					return
				}
				defer cResp.Body.Close()

				if cResp.StatusCode == http.StatusOK {
					atomic.AddInt64(&successCount, 1)
				} else if cResp.StatusCode == http.StatusBadRequest {
					atomic.AddInt64(&failureCount, 1)
				}
			}()
		}

		wg.Wait()

		if successCount != 1 {
			t.Fatalf("expected exactly 1 successful verification among concurrent requests, got %d", successCount)
		}
		if failureCount != concurrentRequests-1 {
			t.Fatalf("expected %d failures among concurrent requests, got %d", concurrentRequests-1, failureCount)
		}
	})
}

func TestE2E_EmailVerification_Manual10StepsVerification(t *testing.T) {
	testDBURL := getTestDatabaseURL()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	dbPool, err := database.NewPostgresPool(ctx, testDBURL)
	if err != nil {
		t.Skipf("skipping test: %v", err)
		return
	}
	defer dbPool.Close()

	emailSender := email.NewInMemorySender()
	userRepo := user.NewPostgresRepository(dbPool)
	hasher := user.NewBcryptHasher(12)
	userService := user.NewService(userRepo, hasher, user.WithEmailSender(emailSender), user.WithTokenLifetime(24*time.Hour))
	verifRepo := verification.NewPostgresRepository(dbPool)
	verifService := verification.NewService(verifRepo)

	grpcHandler := authgrpc.NewServer(userService, nil, authgrpc.WithVerificationService(verifService))
	grpcServer := grpc.NewServer()
	authv1.RegisterAuthServiceServer(grpcServer, grpcHandler)

	grpcListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen gRPC failed: %v", err)
	}
	defer grpcListener.Close()
	go func() { _ = grpcServer.Serve(grpcListener) }()
	defer grpcServer.GracefulStop()

	authConn, err := grpc.NewClient(grpcListener.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial gRPC failed: %v", err)
	}
	defer authConn.Close()

	authClient := authv1.NewAuthServiceClient(authConn)
	gwHandler := gateway.NewHandler(authClient)
	gwRouter := gateway.NewRouter(gwHandler)

	httpListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen HTTP failed: %v", err)
	}
	defer httpListener.Close()
	httpServer := &http.Server{Handler: gwRouter}
	go func() { _ = httpServer.Serve(httpListener) }()
	defer httpServer.Close()

	baseURL := "http://" + httpListener.Addr().String()
	registerURL := baseURL + "/api/v1/auth/register"
	verifyURL := baseURL + "/api/v1/auth/verify-email"

	// 1. Register user
	t.Log("Step 1: Registering user via Gateway...")
	regEmail := "ten_step_user_" + uuid.New().String() + "@kr0n.dev"
	regBody, _ := json.Marshal(map[string]string{
		"email":        regEmail,
		"password":     "Password123!",
		"display_name": "Ten Step User",
	})
	rReq, _ := http.NewRequestWithContext(ctx, http.MethodPost, registerURL, bytes.NewReader(regBody))
	rReq.Header.Set("Content-Type", "application/json")
	rResp, err := http.DefaultClient.Do(rReq)
	if err != nil || rResp.StatusCode != http.StatusCreated {
		t.Fatalf("Step 1 failed: status %d, err: %v", rResp.StatusCode, err)
	}
	var regDTO gateway.RegisterResponseDTO
	_ = json.NewDecoder(rResp.Body).Decode(&regDTO)
	rResp.Body.Close()
	parsedUID, _ := uuid.Parse(regDTO.UserID)
	t.Logf("Step 1 PASSED: Registered user %s", regDTO.UserID)

	// 2. Confirm user is initially unverified
	t.Log("Step 2: Confirming user is initially unverified in PostgreSQL...")
	var initialVerifiedAt *time.Time
	err = dbPool.QueryRow(ctx, "SELECT email_verified_at FROM users WHERE id = $1", parsedUID).Scan(&initialVerifiedAt)
	if err != nil || initialVerifiedAt != nil {
		t.Fatalf("Step 2 failed: expected NULL email_verified_at, got %v", initialVerifiedAt)
	}
	t.Log("Step 2 PASSED: users.email_verified_at IS NULL")

	// 3. Confirm verification token hash exists in PostgreSQL
	t.Log("Step 3: Confirming verification token hash exists in PostgreSQL...")
	sentEmail, ok := emailSender.LastMessage()
	if !ok || sentEmail.Recipient != regEmail {
		t.Fatalf("Step 3 failed: email not captured")
	}
	rawToken := sentEmail.RawToken
	computedHash := verification.HashToken(rawToken)

	var (
		dbTokID       uuid.UUID
		dbTokConsumed *time.Time
	)
	err = dbPool.QueryRow(ctx, "SELECT id, consumed_at FROM email_verification_tokens WHERE token_hash = $1", computedHash).
		Scan(&dbTokID, &dbTokConsumed)
	if err != nil {
		t.Fatalf("Step 3 failed: token hash not found in PostgreSQL: %v", err)
	}
	if dbTokConsumed != nil {
		t.Fatalf("Step 3 failed: token already consumed")
	}
	t.Logf("Step 3 PASSED: verification token hash %s exists in PostgreSQL", computedHash)

	// 4. Confirm raw token does not exist in PostgreSQL
	t.Log("Step 4: Confirming raw token does NOT exist anywhere in PostgreSQL...")
	var rawCount int
	_ = dbPool.QueryRow(ctx, "SELECT count(*) FROM email_verification_tokens WHERE token_hash = $1", rawToken).Scan(&rawCount)
	if rawCount != 0 {
		t.Fatalf("Step 4 failed: raw token found in DB!")
	}
	t.Log("Step 4 PASSED: raw token does not exist in PostgreSQL")

	// 5. Verify email via Gateway
	t.Log("Step 5: Verifying email via Gateway POST /api/v1/auth/verify-email...")
	vBody, _ := json.Marshal(map[string]string{"token": rawToken})
	vReq, _ := http.NewRequestWithContext(ctx, http.MethodPost, verifyURL, bytes.NewReader(vBody))
	vReq.Header.Set("Content-Type", "application/json")
	vResp, err := http.DefaultClient.Do(vReq)
	if err != nil || vResp.StatusCode != http.StatusOK {
		t.Fatalf("Step 5 failed: status %d, err: %v", vResp.StatusCode, err)
	}
	vResp.Body.Close()
	t.Log("Step 5 PASSED: Gateway returned 200 OK")

	// 6. Confirm email_verified_at is populated
	t.Log("Step 6: Confirming users.email_verified_at is populated in PostgreSQL...")
	var populatedVerifiedAt *time.Time
	err = dbPool.QueryRow(ctx, "SELECT email_verified_at FROM users WHERE id = $1", parsedUID).Scan(&populatedVerifiedAt)
	if err != nil || populatedVerifiedAt == nil {
		t.Fatalf("Step 6 failed: email_verified_at is not populated: %v", err)
	}
	t.Logf("Step 6 PASSED: users.email_verified_at is %v", *populatedVerifiedAt)

	// 7. Confirm token is consumed
	t.Log("Step 7: Confirming email_verification_tokens.consumed_at is populated in PostgreSQL...")
	err = dbPool.QueryRow(ctx, "SELECT consumed_at FROM email_verification_tokens WHERE id = $1", dbTokID).Scan(&dbTokConsumed)
	if err != nil || dbTokConsumed == nil {
		t.Fatalf("Step 7 failed: token consumed_at is not populated: %v", err)
	}
	t.Logf("Step 7 PASSED: email_verification_tokens.consumed_at is %v", *dbTokConsumed)

	// 8. Attempt to reuse token
	t.Log("Step 8: Attempting to reuse already-consumed token via Gateway...")
	reuseReq, _ := http.NewRequestWithContext(ctx, http.MethodPost, verifyURL, bytes.NewReader(vBody))
	reuseReq.Header.Set("Content-Type", "application/json")
	reuseResp, err := http.DefaultClient.Do(reuseReq)
	if err != nil {
		t.Fatalf("Step 8 failed: %v", err)
	}

	// 9. Confirm reuse fails
	t.Log("Step 9: Confirming token reuse fails with 400 Bad Request...")
	if reuseResp.StatusCode != http.StatusBadRequest {
		t.Fatalf("Step 9 failed: expected 400 Bad Request, got %d", reuseResp.StatusCode)
	}
	var errDTO gateway.ErrorResponseDTO
	_ = json.NewDecoder(reuseResp.Body).Decode(&errDTO)
	reuseResp.Body.Close()
	if errDTO.Error != "invalid or expired verification token" {
		t.Fatalf("Step 9 failed: expected 'invalid or expired verification token', got %q", errDTO.Error)
	}
	t.Log("Step 9 PASSED: Reuse rejected with 400 Bad Request 'invalid or expired verification token'")

	// 10. Test an expired token
	t.Log("Step 10: Testing an expired token via Gateway...")
	expiredRawToken, _ := verification.GenerateToken()
	expHash := verification.HashToken(expiredRawToken)
	expUID := uuid.New()
	_, _ = dbPool.Exec(ctx, "INSERT INTO users (id, email, display_name, status) VALUES ($1, $2, $3, 'active')",
		expUID, "exp_"+expUID.String()+"@kr0n.dev", "Expired User")
	_, _ = dbPool.Exec(ctx, "INSERT INTO email_verification_tokens (id, user_id, token_hash, expires_at) VALUES ($1, $2, $3, now() - interval '1 hour')",
		uuid.New(), expUID, expHash)

	expBody, _ := json.Marshal(map[string]string{"token": expiredRawToken})
	expReq, _ := http.NewRequestWithContext(ctx, http.MethodPost, verifyURL, bytes.NewReader(expBody))
	expReq.Header.Set("Content-Type", "application/json")
	expResp, err := http.DefaultClient.Do(expReq)
	if err != nil {
		t.Fatalf("Step 10 failed: %v", err)
	}
	if expResp.StatusCode != http.StatusBadRequest {
		t.Fatalf("Step 10 failed: expected 400 Bad Request for expired token, got %d", expResp.StatusCode)
	}
	_ = json.NewDecoder(expResp.Body).Decode(&errDTO)
	expResp.Body.Close()
	if errDTO.Error != "invalid or expired verification token" {
		t.Fatalf("Step 10 failed: expected 'invalid or expired verification token', got %q", errDTO.Error)
	}
	t.Log("Step 10 PASSED: Expired token rejected with 400 Bad Request 'invalid or expired verification token'")
	t.Log("ALL 10 VERIFICATION STEPS COMPLETED SUCCESSFULLY!")
}
