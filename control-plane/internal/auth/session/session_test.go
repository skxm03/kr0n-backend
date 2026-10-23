package session

import (
	"context"
	"encoding/hex"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/skxm03/kr0n-backend/control-plane/internal/auth/user"
)

type mockAuthenticator struct {
	authFunc func(ctx context.Context, params user.AuthenticateParams) (*user.User, error)
}

func (m *mockAuthenticator) Authenticate(ctx context.Context, params user.AuthenticateParams) (*user.User, error) {
	if m.authFunc != nil {
		return m.authFunc(ctx, params)
	}
	return nil, nil
}

type mockSessionRepo struct {
	createFunc            func(ctx context.Context, session *Session) error
	getByTokenHashFunc    func(ctx context.Context, tokenHash string) (*Session, error)
	rotateFunc            func(ctx context.Context, oldTokenHash string, now time.Time, fn RotateFn) (*Session, error)
	revokeByTokenHashFunc func(ctx context.Context, tokenHash string, revokedAt time.Time) error

	created  []*Session
	sessions map[string]*Session
	users    map[uuid.UUID]user.Status
	mu       sync.Mutex
}

func newMockSessionRepo() *mockSessionRepo {
	return &mockSessionRepo{
		sessions: make(map[string]*Session),
		users:    make(map[uuid.UUID]user.Status),
	}
}

func (m *mockSessionRepo) Create(ctx context.Context, session *Session) error {
	if m.createFunc != nil {
		return m.createFunc(ctx, session)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.created = append(m.created, session)
	if m.sessions == nil {
		m.sessions = make(map[string]*Session)
	}
	m.sessions[session.TokenHash] = session
	return nil
}

func (m *mockSessionRepo) GetByTokenHash(ctx context.Context, tokenHash string) (*Session, error) {
	if m.getByTokenHashFunc != nil {
		return m.getByTokenHashFunc(ctx, tokenHash)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	sess, ok := m.sessions[tokenHash]
	if !ok {
		return nil, ErrSessionNotFound
	}
	return sess, nil
}

func (m *mockSessionRepo) Rotate(ctx context.Context, oldTokenHash string, now time.Time, fn RotateFn) (*Session, error) {
	if m.rotateFunc != nil {
		return m.rotateFunc(ctx, oldTokenHash, now, fn)
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	sess, ok := m.sessions[oldTokenHash]
	if !ok {
		return nil, ErrSessionNotFound
	}

	uStatus, ok := m.users[sess.UserID]
	if !ok {
		uStatus = user.StatusActive
	}

	newTokenHash, newExpiresAt, err := fn(sess, uStatus)
	if err != nil {
		return nil, err
	}

	delete(m.sessions, oldTokenHash)
	sess.TokenHash = newTokenHash
	sess.LastSeenAt = now
	sess.ExpiresAt = newExpiresAt
	m.sessions[newTokenHash] = sess

	return sess, nil
}

func (m *mockSessionRepo) RevokeByTokenHash(ctx context.Context, tokenHash string, revokedAt time.Time) error {
	if m.revokeByTokenHashFunc != nil {
		return m.revokeByTokenHashFunc(ctx, tokenHash, revokedAt)
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	sess, ok := m.sessions[tokenHash]
	if ok && sess.RevokedAt == nil {
		sess.RevokedAt = &revokedAt
	}
	return nil
}

type mockTokenIssuer struct {
	issueFunc func(userID uuid.UUID, sessionID uuid.UUID, now time.Time) (accessToken, rawRefreshToken, tokenHash string, expiresIn time.Duration, err error)
}

func (m *mockTokenIssuer) Issue(userID uuid.UUID, sessionID uuid.UUID, now time.Time) (string, string, string, time.Duration, error) {
	if m.issueFunc != nil {
		return m.issueFunc(userID, sessionID, now)
	}
	return "mock_access_token", "mock_raw_refresh", HashRefreshToken("mock_raw_refresh"), 15 * time.Minute, nil
}

func TestSession_HashAndVerify(t *testing.T) {
	token, err := GenerateRefreshToken()
	if err != nil {
		t.Fatalf("GenerateRefreshToken failed: %v", err)
	}
	if len(token) != 64 { // 32 hex bytes = 64 characters
		t.Fatalf("expected 64 character hex string, got %d", len(token))
	}

	hash := HashRefreshToken(token)
	if hash == token {
		t.Fatal("hash should never match raw token")
	}

	if !VerifyRefreshToken(token, hash) {
		t.Fatal("VerifyRefreshToken failed for matching token and hash")
	}

	if VerifyRefreshToken("wrong_token", hash) {
		t.Fatal("VerifyRefreshToken succeeded for mismatched token")
	}
}

func TestJWTSigner_SignAndVerify(t *testing.T) {
	key := []byte("secret_key_at_least_32_bytes_long_1234567")
	issuer := "kr0n-auth"
	lifetime := 15 * time.Minute

	signer, err := NewJWTSigner(key, issuer, lifetime)
	if err != nil {
		t.Fatalf("NewJWTSigner failed: %v", err)
	}

	userID := uuid.New()
	sessionID := uuid.New()
	now := time.Now().UTC()

	token, exp, err := signer.Sign(userID, sessionID, now)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}
	if exp != lifetime {
		t.Fatalf("expected expires_in %v, got %v", lifetime, exp)
	}

	claims, err := signer.Verify(token, now)
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}

	if claims.Issuer != issuer {
		t.Fatalf("expected issuer %s, got %s", issuer, claims.Issuer)
	}
	if claims.Subject != userID.String() {
		t.Fatalf("expected sub %s, got %s", userID.String(), claims.Subject)
	}
	if claims.SessionID != sessionID.String() {
		t.Fatalf("expected sid %s, got %s", sessionID.String(), claims.SessionID)
	}
	if claims.ExpiresAt != now.Add(lifetime).Unix() {
		t.Fatalf("expected exp %v, got %v", now.Add(lifetime).Unix(), claims.ExpiresAt)
	}

	// Test expired token
	futureTime := now.Add(16 * time.Minute)
	_, err = signer.Verify(token, futureTime)
	if !errors.Is(err, ErrTokenExpired) {
		t.Fatalf("expected ErrTokenExpired, got %v", err)
	}

	// Test tampered token
	tampered := token + "tampered"
	_, err = signer.Verify(tampered, now)
	if !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("expected ErrInvalidToken, got %v", err)
	}
}

func TestJWTSigner_InvalidConfiguration(t *testing.T) {
	_, err := NewJWTSigner([]byte("short"), "kr0n-auth", 15*time.Minute)
	if !errors.Is(err, ErrInvalidSignerKey) {
		t.Fatalf("expected ErrInvalidSignerKey, got %v", err)
	}

	_, err = NewJWTSigner([]byte("secret_key_at_least_32_bytes_long_1234567"), "", 15*time.Minute)
	if !errors.Is(err, ErrInvalidIssuer) {
		t.Fatalf("expected ErrInvalidIssuer, got %v", err)
	}

	_, err = NewJWTSigner([]byte("secret_key_at_least_32_bytes_long_1234567"), "kr0n-auth", 0)
	if !errors.Is(err, ErrInvalidLifetime) {
		t.Fatalf("expected ErrInvalidLifetime, got %v", err)
	}
}

func TestService_Login_Success(t *testing.T) {
	userID := uuid.New()
	testUser := &user.User{
		ID:          userID,
		Email:       "user@kr0n.dev",
		DisplayName: "User One",
		Status:      user.StatusActive,
	}

	auth := &mockAuthenticator{
		authFunc: func(ctx context.Context, params user.AuthenticateParams) (*user.User, error) {
			return testUser, nil
		},
	}
	repo := &mockSessionRepo{}
	signer, _ := NewJWTSigner([]byte("secret_key_at_least_32_bytes_long_1234567"), "kr0n-auth", 15*time.Minute)
	issuer := NewDefaultTokenIssuer(signer)

	svc := NewService(auth, repo, issuer, 30*24*time.Hour)

	ua := "Mozilla/5.0"
	clientIP := net.ParseIP("192.168.1.1")

	res, err := svc.Login(context.Background(), LoginParams{
		Email:     "user@kr0n.dev",
		Password:  "password123",
		UserAgent: &ua,
		ClientIP:  &clientIP,
	})
	if err != nil {
		t.Fatalf("Login failed: %v", err)
	}

	if res.AccessToken == "" {
		t.Fatal("expected non-empty access token")
	}
	if res.RefreshToken == "" {
		t.Fatal("expected non-empty refresh token")
	}
	if res.TokenType != "Bearer" {
		t.Fatalf("expected token type Bearer, got %s", res.TokenType)
	}
	if res.User != testUser {
		t.Fatal("expected user in response")
	}

	// Verify session repository persistence
	if len(repo.created) != 1 {
		t.Fatalf("expected 1 session persisted, got %d", len(repo.created))
	}
	createdSession := repo.created[0]
	if createdSession.UserID != userID {
		t.Fatalf("expected session userID %s, got %s", userID, createdSession.UserID)
	}
	if createdSession.TokenHash == res.RefreshToken {
		t.Fatal("session table must NOT store raw refresh token")
	}
	if !VerifyRefreshToken(res.RefreshToken, createdSession.TokenHash) {
		t.Fatal("stored hash must verify against returned refresh token")
	}
	if createdSession.UserAgent == nil || *createdSession.UserAgent != ua {
		t.Fatal("session UserAgent mismatch")
	}
	if createdSession.IPAddress == nil || !createdSession.IPAddress.Equal(clientIP) {
		t.Fatal("session IPAddress mismatch")
	}
}

func TestService_Login_InvalidCredentials(t *testing.T) {
	auth := &mockAuthenticator{
		authFunc: func(ctx context.Context, params user.AuthenticateParams) (*user.User, error) {
			return nil, user.ErrInvalidCredentials
		},
	}
	repo := &mockSessionRepo{}
	signer, _ := NewJWTSigner([]byte("secret_key_at_least_32_bytes_long_1234567"), "kr0n-auth", 15*time.Minute)
	issuer := NewDefaultTokenIssuer(signer)

	svc := NewService(auth, repo, issuer, 30*24*time.Hour)

	_, err := svc.Login(context.Background(), LoginParams{
		Email:    "unknown@kr0n.dev",
		Password: "wrong",
	})
	if !errors.Is(err, user.ErrInvalidCredentials) {
		t.Fatalf("expected ErrInvalidCredentials, got %v", err)
	}

	if len(repo.created) != 0 {
		t.Fatal("expected no sessions created on failed authentication")
	}
}

func TestService_Login_InactiveUser(t *testing.T) {
	auth := &mockAuthenticator{
		authFunc: func(ctx context.Context, params user.AuthenticateParams) (*user.User, error) {
			return nil, user.ErrUserNotActive
		},
	}
	repo := &mockSessionRepo{}
	signer, _ := NewJWTSigner([]byte("secret_key_at_least_32_bytes_long_1234567"), "kr0n-auth", 15*time.Minute)
	issuer := NewDefaultTokenIssuer(signer)

	svc := NewService(auth, repo, issuer, 30*24*time.Hour)

	_, err := svc.Login(context.Background(), LoginParams{
		Email:    "inactive@kr0n.dev",
		Password: "password123",
	})
	if !errors.Is(err, user.ErrUserNotActive) {
		t.Fatalf("expected ErrUserNotActive, got %v", err)
	}

	if len(repo.created) != 0 {
		t.Fatal("expected no sessions created for inactive user")
	}
}

func TestService_Login_TokenIssuerFailure(t *testing.T) {
	auth := &mockAuthenticator{
		authFunc: func(ctx context.Context, params user.AuthenticateParams) (*user.User, error) {
			return &user.User{ID: uuid.New(), Status: user.StatusActive}, nil
		},
	}
	repo := &mockSessionRepo{}
	issuer := &mockTokenIssuer{
		issueFunc: func(userID uuid.UUID, sessionID uuid.UUID, now time.Time) (string, string, string, time.Duration, error) {
			return "", "", "", 0, errors.New("crypto entropy error")
		},
	}

	svc := NewService(auth, repo, issuer, 30*24*time.Hour)

	_, err := svc.Login(context.Background(), LoginParams{
		Email:    "user@kr0n.dev",
		Password: "password123",
	})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if len(repo.created) != 0 {
		t.Fatal("expected no session persisted when token issuance fails")
	}
}

func TestService_Login_SessionRepoFailure(t *testing.T) {
	auth := &mockAuthenticator{
		authFunc: func(ctx context.Context, params user.AuthenticateParams) (*user.User, error) {
			return &user.User{ID: uuid.New(), Status: user.StatusActive}, nil
		},
	}
	repo := &mockSessionRepo{
		createFunc: func(ctx context.Context, session *Session) error {
			return errors.New("db disk full")
		},
	}
	signer, _ := NewJWTSigner([]byte("secret_key_at_least_32_bytes_long_1234567"), "kr0n-auth", 15*time.Minute)
	issuer := NewDefaultTokenIssuer(signer)

	svc := NewService(auth, repo, issuer, 30*24*time.Hour)

	res, err := svc.Login(context.Background(), LoginParams{
		Email:    "user@kr0n.dev",
		Password: "password123",
	})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if res != nil {
		t.Fatal("tokens must NOT be returned when session persistence fails")
	}
}

func TestRefreshToken_RandomnessAndFormat(t *testing.T) {
	seen := make(map[string]bool)
	const count = 100

	for i := 0; i < count; i++ {
		token, err := GenerateRefreshToken()
		if err != nil {
			t.Fatalf("GenerateRefreshToken failed on iter %d: %v", i, err)
		}
		if len(token) != 64 {
			t.Fatalf("expected 64 hex characters, got %d", len(token))
		}
		rawBytes, err := hex.DecodeString(token)
		if err != nil {
			t.Fatalf("expected valid hex string, got error: %v", err)
		}
		if len(rawBytes) != 32 {
			t.Fatalf("expected 32 decoded bytes, got %d", len(rawBytes))
		}
		if seen[token] {
			t.Fatalf("duplicate refresh token detected: %s", token)
		}
		seen[token] = true
	}
}

func TestSession_ModelInvariants(t *testing.T) {
	now := time.Now().UTC()
	sessID := uuid.New()
	userID := uuid.New()
	rawToken, _ := GenerateRefreshToken()
	tokenHash := HashRefreshToken(rawToken)

	sess := &Session{
		ID:         sessID,
		UserID:     userID,
		TokenHash:  tokenHash,
		ExpiresAt:  now.Add(30 * 24 * time.Hour),
		RevokedAt:  nil,
		CreatedAt:  now,
		LastSeenAt: now,
	}

	// 1. Valid active session
	if sess.RevokedAt != nil {
		t.Fatal("expected active session revoked_at to be nil")
	}
	if !sess.ExpiresAt.After(now) {
		t.Fatal("expected active session expires_at to be in the future")
	}

	// 2. Token replacement / rotation on model
	newRawToken, _ := GenerateRefreshToken()
	newTokenHash := HashRefreshToken(newRawToken)
	rotatedAt := now.Add(5 * time.Minute)

	sess.TokenHash = newTokenHash
	sess.LastSeenAt = rotatedAt
	sess.ExpiresAt = rotatedAt.Add(30 * 24 * time.Hour)

	if sess.TokenHash != newTokenHash {
		t.Fatal("token replacement failed")
	}
	if sess.LastSeenAt != rotatedAt {
		t.Fatal("last seen update failed")
	}

	// 3. Revocation
	revokedAt := rotatedAt.Add(1 * time.Minute)
	sess.RevokedAt = &revokedAt
	if sess.RevokedAt == nil || *sess.RevokedAt != revokedAt {
		t.Fatal("session revocation failed")
	}

	// 4. Expired session
	expiredSess := &Session{
		ID:        uuid.New(),
		UserID:    userID,
		TokenHash: tokenHash,
		ExpiresAt: now.Add(-1 * time.Hour),
	}
	if expiredSess.ExpiresAt.After(now) {
		t.Fatal("expected session to be expired")
	}
}

func TestJWT_ClaimsVerification(t *testing.T) {
	key := []byte("secret_key_at_least_32_bytes_long_1234567")
	issuer := "kr0n-auth"
	lifetime := 15 * time.Minute

	signer, err := NewJWTSigner(key, issuer, lifetime)
	if err != nil {
		t.Fatalf("NewJWTSigner failed: %v", err)
	}

	userID := uuid.New()
	sessID := uuid.New()
	now := time.Now().UTC()

	token, exp, err := signer.Sign(userID, sessID, now)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}
	if exp != lifetime {
		t.Fatalf("expected lifetime %v, got %v", lifetime, exp)
	}

	claims, err := signer.Verify(token, now)
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}

	if claims.Issuer != issuer {
		t.Fatalf("expected issuer %s, got %s", issuer, claims.Issuer)
	}
	if claims.Subject != userID.String() {
		t.Fatalf("expected sub %s, got %s", userID.String(), claims.Subject)
	}
	if claims.SessionID != sessID.String() {
		t.Fatalf("expected sid %s, got %s", sessID.String(), claims.SessionID)
	}
	if claims.IssuedAt != now.Unix() {
		t.Fatalf("expected iat %d, got %d", now.Unix(), claims.IssuedAt)
	}
	if claims.ExpiresAt != now.Add(lifetime).Unix() {
		t.Fatalf("expected exp %d, got %d", now.Add(lifetime).Unix(), claims.ExpiresAt)
	}
}

func setupTestSessionService() (*Service, *mockSessionRepo, *user.User, string, *Session) {
	userID := uuid.New()
	testUser := &user.User{
		ID:          userID,
		Email:       "service_test@kr0n.dev",
		DisplayName: "Service Test User",
		Status:      user.StatusActive,
	}

	auth := &mockAuthenticator{
		authFunc: func(ctx context.Context, params user.AuthenticateParams) (*user.User, error) {
			return testUser, nil
		},
	}
	repo := newMockSessionRepo()
	repo.users[userID] = user.StatusActive

	signer, _ := NewJWTSigner([]byte("secret_key_at_least_32_bytes_long_1234567"), "kr0n-auth", 15*time.Minute)
	issuer := NewDefaultTokenIssuer(signer)
	svc := NewService(auth, repo, issuer, 30*24*time.Hour)

	rawRefresh, _ := GenerateRefreshToken()
	tokenHash := HashRefreshToken(rawRefresh)
	now := time.Now().UTC()
	sess := &Session{
		ID:         uuid.New(),
		UserID:     userID,
		TokenHash:  tokenHash,
		ExpiresAt:  now.Add(30 * 24 * time.Hour),
		RevokedAt:  nil,
		CreatedAt:  now,
		LastSeenAt: now,
	}
	_ = repo.Create(context.Background(), sess)

	return svc, repo, testUser, rawRefresh, sess
}

func TestService_Refresh_Success(t *testing.T) {
	svc, repo, testUser, rawRefresh, initialSess := setupTestSessionService()
	ctx := context.Background()

	res, err := svc.Refresh(ctx, rawRefresh)
	if err != nil {
		t.Fatalf("Refresh failed: %v", err)
	}

	if res.AccessToken == "" {
		t.Fatal("expected non-empty access token")
	}
	if res.RefreshToken == "" {
		t.Fatal("expected non-empty refresh token")
	}
	if res.RefreshToken == rawRefresh {
		t.Fatal("refresh token must be rotated to a new token")
	}
	if res.TokenType != "Bearer" {
		t.Fatalf("expected Bearer token type, got %s", res.TokenType)
	}
	if res.ExpiresIn != 15*time.Minute {
		t.Fatalf("expected 15m expires in, got %v", res.ExpiresIn)
	}

	// Verify old token is gone and new token is in repo
	_, err = repo.GetByTokenHash(ctx, HashRefreshToken(rawRefresh))
	if !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("expected old token hash to be not found, got %v", err)
	}

	newSess, err := repo.GetByTokenHash(ctx, HashRefreshToken(res.RefreshToken))
	if err != nil {
		t.Fatalf("expected new token hash in repo: %v", err)
	}
	if newSess.ID != initialSess.ID {
		t.Fatalf("expected same session ID %s, got %s", initialSess.ID, newSess.ID)
	}
	if newSess.UserID != testUser.ID {
		t.Fatalf("expected same user ID %s, got %s", testUser.ID, newSess.UserID)
	}
}

func TestService_Refresh_InvalidToken(t *testing.T) {
	svc, _, _, _, _ := setupTestSessionService()
	ctx := context.Background()

	// Empty token
	_, err := svc.Refresh(ctx, "")
	if !errors.Is(err, ErrInvalidRefreshToken) {
		t.Fatalf("expected ErrInvalidRefreshToken for empty token, got %v", err)
	}

	// Whitespace token
	_, err = svc.Refresh(ctx, "   ")
	if !errors.Is(err, ErrInvalidRefreshToken) {
		t.Fatalf("expected ErrInvalidRefreshToken for whitespace token, got %v", err)
	}

	// Nonexistent token
	nonexistentToken, _ := GenerateRefreshToken()
	_, err = svc.Refresh(ctx, nonexistentToken)
	if !errors.Is(err, ErrInvalidRefreshToken) {
		t.Fatalf("expected ErrInvalidRefreshToken for nonexistent token, got %v", err)
	}
}

func TestService_Refresh_ExpiredSession(t *testing.T) {
	svc, repo, _, rawRefresh, sess := setupTestSessionService()
	ctx := context.Background()

	// Expire the session in repo
	sess.ExpiresAt = time.Now().UTC().Add(-1 * time.Hour)
	repo.sessions[sess.TokenHash] = sess

	_, err := svc.Refresh(ctx, rawRefresh)
	if !errors.Is(err, ErrSessionExpired) {
		t.Fatalf("expected ErrSessionExpired, got %v", err)
	}
}

func TestService_Refresh_RevokedSession(t *testing.T) {
	svc, repo, _, rawRefresh, sess := setupTestSessionService()
	ctx := context.Background()

	// Revoke the session in repo
	revokedAt := time.Now().UTC()
	sess.RevokedAt = &revokedAt
	repo.sessions[sess.TokenHash] = sess

	_, err := svc.Refresh(ctx, rawRefresh)
	if !errors.Is(err, ErrSessionRevoked) {
		t.Fatalf("expected ErrSessionRevoked, got %v", err)
	}
}

func TestService_Refresh_InactiveUser(t *testing.T) {
	svc, repo, testUser, rawRefresh, _ := setupTestSessionService()
	ctx := context.Background()

	// Mark user as suspended
	repo.users[testUser.ID] = user.StatusSuspended

	_, err := svc.Refresh(ctx, rawRefresh)
	if !errors.Is(err, user.ErrUserNotActive) {
		t.Fatalf("expected ErrUserNotActive, got %v", err)
	}
}

func TestService_Refresh_RotationCycle(t *testing.T) {
	svc, _, _, initialToken, _ := setupTestSessionService()
	ctx := context.Background()

	// 1. First refresh rotates initial token
	res1, err := svc.Refresh(ctx, initialToken)
	if err != nil {
		t.Fatalf("first refresh failed: %v", err)
	}

	// 2. Old token must fail
	_, err = svc.Refresh(ctx, initialToken)
	if !errors.Is(err, ErrInvalidRefreshToken) {
		t.Fatalf("expected old refresh token to fail after rotation, got %v", err)
	}

	// 3. New token succeeds
	res2, err := svc.Refresh(ctx, res1.RefreshToken)
	if err != nil {
		t.Fatalf("refresh with new rotated token failed: %v", err)
	}
	if res2.RefreshToken == res1.RefreshToken {
		t.Fatal("expected second rotation to produce another fresh token")
	}

	// 4. Old rotated token from first refresh must now fail
	_, err = svc.Refresh(ctx, res1.RefreshToken)
	if !errors.Is(err, ErrInvalidRefreshToken) {
		t.Fatalf("expected first rotated token to fail after second rotation, got %v", err)
	}
}

func TestService_Logout_RevokesSession(t *testing.T) {
	svc, repo, _, rawRefresh, sess := setupTestSessionService()
	ctx := context.Background()

	err := svc.Logout(ctx, rawRefresh)
	if err != nil {
		t.Fatalf("Logout failed: %v", err)
	}

	// Session row must still exist (not deleted)
	updatedSess, err := repo.GetByTokenHash(ctx, sess.TokenHash)
	if err != nil {
		t.Fatalf("session must not be deleted: %v", err)
	}
	if updatedSess.RevokedAt == nil {
		t.Fatal("expected session revoked_at to be set")
	}

	// Subsequent refresh attempts must fail
	_, err = svc.Refresh(ctx, rawRefresh)
	if !errors.Is(err, ErrSessionRevoked) {
		t.Fatalf("expected ErrSessionRevoked after logout, got %v", err)
	}
}

func TestService_Logout_SafeAndIdempotent(t *testing.T) {
	svc, _, _, rawRefresh, _ := setupTestSessionService()
	ctx := context.Background()

	// Logout with invalid token is safe/idempotent
	if err := svc.Logout(ctx, "invalid_random_token_123"); err != nil {
		t.Fatalf("expected nil on invalid token logout, got %v", err)
	}
	if err := svc.Logout(ctx, ""); err != nil {
		t.Fatalf("expected nil on empty token logout, got %v", err)
	}

	// Calling logout twice with valid token is idempotent
	if err := svc.Logout(ctx, rawRefresh); err != nil {
		t.Fatalf("first logout failed: %v", err)
	}
	if err := svc.Logout(ctx, rawRefresh); err != nil {
		t.Fatalf("second logout must be idempotent and succeed: %v", err)
	}
}

func TestService_Refresh_ConcurrentRequestsPreventDoubleRotation(t *testing.T) {
	svc, _, _, rawRefresh, _ := setupTestSessionService()
	ctx := context.Background()

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
			_, err := svc.Refresh(ctx, rawRefresh)
			mu.Lock()
			defer mu.Unlock()
			if err == nil {
				successCount++
			} else {
				failureCount++
			}
		}()
	}
	wg.Wait()

	if successCount != 1 {
		t.Fatalf("expected exactly 1 concurrent refresh to succeed, got %d", successCount)
	}
	if failureCount != concurrency-1 {
		t.Fatalf("expected exactly %d concurrent refreshes to fail, got %d", concurrency-1, failureCount)
	}
}
