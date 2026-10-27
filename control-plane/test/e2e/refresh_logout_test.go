package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/skxm03/kr0n-backend/control-plane/internal/auth/repository"
	"github.com/skxm03/kr0n-backend/control-plane/internal/gateway"
)

func TestE2E_Refresh_Logout_Lifecycle(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	dbPool, baseURL, cleanup := startE2ECluster(t, ctx)
	if dbPool == nil {
		return
	}
	defer cleanup()

	registerURL := baseURL + "/api/v1/auth/register"
	loginURL := baseURL + "/api/v1/auth/login"
	refreshURL := baseURL + "/api/v1/auth/refresh"
	logoutURL := baseURL + "/api/v1/auth/logout"

	uniqueID := uuid.New().String()
	email := "e2e_lifecycle_" + uniqueID + "@kr0n.dev"
	password := "SecureLifecyclePass123!"
	displayName := "E2E Lifecycle User"

	// 1. REGISTER
	regBody, _ := json.Marshal(map[string]string{
		"email":        email,
		"password":     password,
		"display_name": displayName,
	})
	regReq, _ := http.NewRequestWithContext(ctx, http.MethodPost, registerURL, bytes.NewReader(regBody))
	regReq.Header.Set("Content-Type", "application/json")

	regResp, err := http.DefaultClient.Do(regReq)
	if err != nil {
		t.Fatalf("register failed: %v", err)
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
		t.Fatalf("parse user id failed: %v", err)
	}

	// 2. LOGIN
	loginBody, _ := json.Marshal(map[string]string{
		"email":    email,
		"password": password,
	})
	loginReq, _ := http.NewRequestWithContext(ctx, http.MethodPost, loginURL, bytes.NewReader(loginBody))
	loginReq.Header.Set("Content-Type", "application/json")
	loginReq.Header.Set("User-Agent", "kr0n-lifecycle-agent/1.0")

	loginResp, err := http.DefaultClient.Do(loginReq)
	if err != nil {
		t.Fatalf("login failed: %v", err)
	}
	defer loginResp.Body.Close()
	if loginResp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(loginResp.Body)
		t.Fatalf("expected 200 OK on login, got %d: %s", loginResp.StatusCode, string(b))
	}

	var loginData gateway.LoginResponseDTO
	_ = json.NewDecoder(loginResp.Body).Decode(&loginData)

	initialAccess := loginData.AccessToken
	initialRefresh := loginData.RefreshToken

	if initialAccess == "" || initialRefresh == "" {
		t.Fatal("expected non-empty tokens from login")
	}

	// Verify database state: raw token never stored
	var (
		storedHash    string
		sessionID     uuid.UUID
		storedRevoked *time.Time
		lastSeenAt    time.Time
	)
	err = dbPool.QueryRow(ctx, `
		SELECT id, token_hash, revoked_at, last_seen_at
		FROM sessions WHERE user_id = $1
	`, userID).Scan(&sessionID, &storedHash, &storedRevoked, &lastSeenAt)
	if err != nil {
		t.Fatalf("query session failed: %v", err)
	}
	if storedHash == initialRefresh {
		t.Fatal("SECURITY VIOLATION: raw refresh token is stored in PostgreSQL!")
	}
	if !repository.VerifyRefreshToken(initialRefresh, storedHash) {
		t.Fatal("stored hash does not match initial refresh token")
	}
	if storedRevoked != nil {
		t.Fatal("expected active session revoked_at to be NULL")
	}

	// Sleep 1.1 seconds so that unix timestamp in seconds advances, producing fresh iat/exp
	time.Sleep(1100 * time.Millisecond)

	// 3. REFRESH
	refBody, _ := json.Marshal(map[string]string{
		"refresh_token": initialRefresh,
	})
	refReq, _ := http.NewRequestWithContext(ctx, http.MethodPost, refreshURL, bytes.NewReader(refBody))
	refReq.Header.Set("Content-Type", "application/json")

	refResp, err := http.DefaultClient.Do(refReq)
	if err != nil {
		t.Fatalf("refresh request failed: %v", err)
	}
	defer refResp.Body.Close()
	if refResp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(refResp.Body)
		t.Fatalf("expected 200 OK on refresh, got %d: %s", refResp.StatusCode, string(b))
	}

	var refData gateway.RefreshResponseDTO
	_ = json.NewDecoder(refResp.Body).Decode(&refData)

	if refData.AccessToken == "" || refData.RefreshToken == "" {
		t.Fatal("expected non-empty tokens on refresh")
	}
	if refData.AccessToken == initialAccess {
		t.Fatal("expected fresh access token after refresh")
	}
	if refData.RefreshToken == initialRefresh {
		t.Fatal("expected rotated refresh token after refresh")
	}
	if refData.TokenType != "Bearer" {
		t.Fatalf("expected Bearer token type, got %s", refData.TokenType)
	}
	if refData.ExpiresIn != 900 {
		t.Fatalf("expected 900s expiration, got %d", refData.ExpiresIn)
	}

	// Verify database: same session ID, updated token hash, updated last_seen_at
	var (
		newStoredHash   string
		updatedSessID   uuid.UUID
		updatedLastSeen time.Time
	)
	err = dbPool.QueryRow(ctx, `
		SELECT id, token_hash, last_seen_at
		FROM sessions WHERE id = $1
	`, sessionID).Scan(&updatedSessID, &newStoredHash, &updatedLastSeen)
	if err != nil {
		t.Fatalf("query updated session failed: %v", err)
	}
	if updatedSessID != sessionID {
		t.Fatalf("expected same session ID %s, got %s", sessionID, updatedSessID)
	}
	if newStoredHash == refData.RefreshToken {
		t.Fatal("SECURITY VIOLATION: raw refresh token is stored in PostgreSQL!")
	}
	if !repository.VerifyRefreshToken(refData.RefreshToken, newStoredHash) {
		t.Fatal("stored hash does not match rotated refresh token")
	}
	if repository.VerifyRefreshToken(initialRefresh, newStoredHash) {
		t.Fatal("old refresh token must no longer match database hash")
	}

	// 4. VERIFY NEW REFRESH TOKEN SUCCEEDS (SECOND ROTATION)
	newRefBody, _ := json.Marshal(map[string]string{
		"refresh_token": refData.RefreshToken,
	})
	newRefReq, _ := http.NewRequestWithContext(ctx, http.MethodPost, refreshURL, bytes.NewReader(newRefBody))
	newRefReq.Header.Set("Content-Type", "application/json")

	newRefResp, err := http.DefaultClient.Do(newRefReq)
	if err != nil {
		t.Fatalf("second refresh request failed: %v", err)
	}
	defer newRefResp.Body.Close()
	if newRefResp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(newRefResp.Body)
		t.Fatalf("expected 200 OK on second refresh, got %d: %s", newRefResp.StatusCode, string(b))
	}

	var secondRefData gateway.RefreshResponseDTO
	_ = json.NewDecoder(newRefResp.Body).Decode(&secondRefData)

	latestRefreshToken := secondRefData.RefreshToken

	// 5. VERIFY OLD REFRESH TOKEN FAILS AFTER ROTATION AND REVOKES SESSION ON REUSE
	oldRefBody, _ := json.Marshal(map[string]string{
		"refresh_token": initialRefresh,
	})
	oldRefReq, _ := http.NewRequestWithContext(ctx, http.MethodPost, refreshURL, bytes.NewReader(oldRefBody))
	oldRefReq.Header.Set("Content-Type", "application/json")

	oldRefResp, err := http.DefaultClient.Do(oldRefReq)
	if err != nil {
		t.Fatalf("old refresh request failed: %v", err)
	}
	defer oldRefResp.Body.Close()
	if oldRefResp.StatusCode != http.StatusUnauthorized {
		b, _ := io.ReadAll(oldRefResp.Body)
		t.Fatalf("expected 401 Unauthorized for reused old refresh token, got %d: %s", oldRefResp.StatusCode, string(b))
	}

	var errResp gateway.ErrorResponseDTO
	_ = json.NewDecoder(oldRefResp.Body).Decode(&errResp)
	if errResp.Error != "invalid refresh token" {
		t.Fatalf("expected 'invalid refresh token', got %s", errResp.Error)
	}
	if errResp.Code != "UNAUTHORIZED" {
		t.Fatalf("expected code UNAUTHORIZED, got %s", errResp.Code)
	}

	// 6. LOGOUT
	logoutBody, _ := json.Marshal(map[string]string{
		"refresh_token": latestRefreshToken,
	})
	logoutReq, _ := http.NewRequestWithContext(ctx, http.MethodPost, logoutURL, bytes.NewReader(logoutBody))
	logoutReq.Header.Set("Content-Type", "application/json")

	logoutResp, err := http.DefaultClient.Do(logoutReq)
	if err != nil {
		t.Fatalf("logout request failed: %v", err)
	}
	defer logoutResp.Body.Close()
	if logoutResp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(logoutResp.Body)
		t.Fatalf("expected 200 OK on logout, got %d: %s", logoutResp.StatusCode, string(b))
	}

	// 7. VERIFY REFRESH AFTER LOGOUT FAILS
	postLogoutReq, _ := http.NewRequestWithContext(ctx, http.MethodPost, refreshURL, bytes.NewReader(logoutBody))
	postLogoutReq.Header.Set("Content-Type", "application/json")

	postLogoutResp, err := http.DefaultClient.Do(postLogoutReq)
	if err != nil {
		t.Fatalf("post-logout refresh request failed: %v", err)
	}
	defer postLogoutResp.Body.Close()
	if postLogoutResp.StatusCode != http.StatusUnauthorized {
		b, _ := io.ReadAll(postLogoutResp.Body)
		t.Fatalf("expected 401 Unauthorized after logout, got %d: %s", postLogoutResp.StatusCode, string(b))
	}

	// 8. VERIFY DATABASE ROW IS NOT DELETED AND REVOKED_AT IS SET
	var (
		postLogoutRevoked *time.Time
		totalSessionCount int
	)
	err = dbPool.QueryRow(ctx, "SELECT count(*) FROM sessions WHERE id = $1", sessionID).Scan(&totalSessionCount)
	if err != nil || totalSessionCount != 1 {
		t.Fatalf("expected session row to be retained, count=%d, err=%v", totalSessionCount, err)
	}
	err = dbPool.QueryRow(ctx, "SELECT revoked_at FROM sessions WHERE id = $1", sessionID).Scan(&postLogoutRevoked)
	if err != nil || postLogoutRevoked == nil {
		t.Fatalf("expected revoked_at to be persisted in DB, got %v", postLogoutRevoked)
	}
}

func TestE2E_Refresh_EdgeCases(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	dbPool, baseURL, cleanup := startE2ECluster(t, ctx)
	if dbPool == nil {
		return
	}
	defer cleanup()

	registerURL := baseURL + "/api/v1/auth/register"
	loginURL := baseURL + "/api/v1/auth/login"
	refreshURL := baseURL + "/api/v1/auth/refresh"

	// 1. Unknown refresh token
	t.Run("unknown refresh token returns generic 401", func(t *testing.T) {
		body, _ := json.Marshal(map[string]string{
			"refresh_token": "nonexistent_opaque_token_string_12345",
		})
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, refreshURL, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("expected 401 Unauthorized, got %d", resp.StatusCode)
		}
		var errResp gateway.ErrorResponseDTO
		_ = json.NewDecoder(resp.Body).Decode(&errResp)
		if errResp.Error != "invalid refresh token" {
			t.Fatalf("expected 'invalid refresh token', got %s", errResp.Error)
		}
	})

	// Setup a user & session for DB manipulation tests
	uniqueID := uuid.New().String()
	email := "e2e_edge_" + uniqueID + "@kr0n.dev"
	password := "SecureEdgePass123!"

	regBody, _ := json.Marshal(map[string]string{
		"email":        email,
		"password":     password,
		"display_name": "Edge User",
	})
	rReq, _ := http.NewRequestWithContext(ctx, http.MethodPost, registerURL, bytes.NewReader(regBody))
	rReq.Header.Set("Content-Type", "application/json")
	rResp, _ := http.DefaultClient.Do(rReq)
	rResp.Body.Close()

	lBody, _ := json.Marshal(map[string]string{
		"email":    email,
		"password": password,
	})
	lReq, _ := http.NewRequestWithContext(ctx, http.MethodPost, loginURL, bytes.NewReader(lBody))
	lReq.Header.Set("Content-Type", "application/json")
	lResp, _ := http.DefaultClient.Do(lReq)
	var lData gateway.LoginResponseDTO
	_ = json.NewDecoder(lResp.Body).Decode(&lData)
	lResp.Body.Close()

	refreshToken := lData.RefreshToken

	// 2. Expired session
	t.Run("expired session fails with generic 401", func(t *testing.T) {
		_, err := dbPool.Exec(ctx, "UPDATE sessions SET expires_at = now() - interval '10 minutes' WHERE user_id = $1", lData.User.ID)
		if err != nil {
			t.Fatalf("expire session failed: %v", err)
		}

		body, _ := json.Marshal(map[string]string{
			"refresh_token": refreshToken,
		})
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, refreshURL, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("expected 401 Unauthorized for expired session, got %d", resp.StatusCode)
		}
		var errResp gateway.ErrorResponseDTO
		_ = json.NewDecoder(resp.Body).Decode(&errResp)
		if errResp.Error != "invalid refresh token" {
			t.Fatalf("expected masked error 'invalid refresh token', got %s", errResp.Error)
		}
	})

	// Reset expiration and test Revoked session
	t.Run("revoked session fails with generic 401", func(t *testing.T) {
		_, err := dbPool.Exec(ctx, "UPDATE sessions SET expires_at = now() + interval '30 days', revoked_at = now() WHERE user_id = $1", lData.User.ID)
		if err != nil {
			t.Fatalf("revoke session failed: %v", err)
		}

		body, _ := json.Marshal(map[string]string{
			"refresh_token": refreshToken,
		})
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, refreshURL, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("expected 401 Unauthorized for revoked session, got %d", resp.StatusCode)
		}
		var errResp gateway.ErrorResponseDTO
		_ = json.NewDecoder(resp.Body).Decode(&errResp)
		if errResp.Error != "invalid refresh token" {
			t.Fatalf("expected masked error 'invalid refresh token', got %s", errResp.Error)
		}
	})

	// Test Inactive/Suspended user
	t.Run("inactive user fails refresh with 403 Forbidden", func(t *testing.T) {
		// Create fresh active user and session
		user2Email := "inactive_refresh_" + uuid.New().String() + "@kr0n.dev"
		r2Body, _ := json.Marshal(map[string]string{
			"email":        user2Email,
			"password":     password,
			"display_name": "Suspended User",
		})
		r2Req, _ := http.NewRequestWithContext(ctx, http.MethodPost, registerURL, bytes.NewReader(r2Body))
		r2Req.Header.Set("Content-Type", "application/json")
		r2Resp, _ := http.DefaultClient.Do(r2Req)
		r2Resp.Body.Close()

		l2Body, _ := json.Marshal(map[string]string{
			"email":    user2Email,
			"password": password,
		})
		l2Req, _ := http.NewRequestWithContext(ctx, http.MethodPost, loginURL, bytes.NewReader(l2Body))
		l2Req.Header.Set("Content-Type", "application/json")
		l2Resp, _ := http.DefaultClient.Do(l2Req)
		var l2Data gateway.LoginResponseDTO
		_ = json.NewDecoder(l2Resp.Body).Decode(&l2Data)
		l2Resp.Body.Close()

		// Suspend user
		_, err := dbPool.Exec(ctx, "UPDATE users SET status = 'suspended' WHERE id = $1", l2Data.User.ID)
		if err != nil {
			t.Fatalf("update status failed: %v", err)
		}

		body, _ := json.Marshal(map[string]string{
			"refresh_token": l2Data.RefreshToken,
		})
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, refreshURL, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("expected 403 Forbidden for suspended user, got %d", resp.StatusCode)
		}
		var errResp gateway.ErrorResponseDTO
		_ = json.NewDecoder(resp.Body).Decode(&errResp)
		if errResp.Error != "user account is not active" {
			t.Fatalf("expected 'user account is not active', got %s", errResp.Error)
		}
	})
}

func TestE2E_Refresh_ConcurrentRequests(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	dbPool, baseURL, cleanup := startE2ECluster(t, ctx)
	if dbPool == nil {
		return
	}
	defer cleanup()

	registerURL := baseURL + "/api/v1/auth/register"
	loginURL := baseURL + "/api/v1/auth/login"
	refreshURL := baseURL + "/api/v1/auth/refresh"

	uniqueID := uuid.New().String()
	email := "e2e_concurrent_" + uniqueID + "@kr0n.dev"
	password := "SecureConcurrentPass123!"

	// Register & Login
	regBody, _ := json.Marshal(map[string]string{
		"email":        email,
		"password":     password,
		"display_name": "Concurrent User",
	})
	rReq, _ := http.NewRequestWithContext(ctx, http.MethodPost, registerURL, bytes.NewReader(regBody))
	rReq.Header.Set("Content-Type", "application/json")
	rResp, _ := http.DefaultClient.Do(rReq)
	rResp.Body.Close()

	lBody, _ := json.Marshal(map[string]string{
		"email":    email,
		"password": password,
	})
	lReq, _ := http.NewRequestWithContext(ctx, http.MethodPost, loginURL, bytes.NewReader(lBody))
	lReq.Header.Set("Content-Type", "application/json")
	lResp, _ := http.DefaultClient.Do(lReq)
	var lData gateway.LoginResponseDTO
	_ = json.NewDecoder(lResp.Body).Decode(&lData)
	lResp.Body.Close()

	tokenToRotate := lData.RefreshToken

	const concurrency = 10
	var (
		wg           sync.WaitGroup
		successCount int
		failureCount int
		mu           sync.Mutex
	)

	wg.Add(concurrency)
	for i := 0; i < concurrency; i++ {
		go func() {
			defer wg.Done()
			body, _ := json.Marshal(map[string]string{
				"refresh_token": tokenToRotate,
			})
			req, _ := http.NewRequestWithContext(ctx, http.MethodPost, refreshURL, bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")

			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				return
			}
			defer resp.Body.Close()

			mu.Lock()
			defer mu.Unlock()
			if resp.StatusCode == http.StatusOK {
				successCount++
			} else if resp.StatusCode == http.StatusUnauthorized {
				failureCount++
			}
		}()
	}
	wg.Wait()

	if successCount != 1 {
		t.Fatalf("expected exactly 1 concurrent refresh request to succeed, got %d", successCount)
	}
	if failureCount != concurrency-1 {
		t.Fatalf("expected exactly %d concurrent refresh requests to fail with 401, got %d", concurrency-1, failureCount)
	}
}
