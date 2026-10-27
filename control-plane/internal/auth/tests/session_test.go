package tests

import (
	"context"
	"encoding/hex"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/skxm03/kr0n-backend/control-plane/internal/auth/jwtkeys"
	"github.com/skxm03/kr0n-backend/control-plane/internal/auth/repository"
	"github.com/skxm03/kr0n-backend/control-plane/internal/auth/service"
)

type mockAuthenticator struct {
	authFunc func(ctx context.Context, params service.AuthenticateParams) (*repository.User, error)
}

func (m *mockAuthenticator) Authenticate(ctx context.Context, params service.AuthenticateParams) (*repository.User, error) {
	if m.authFunc != nil {
		return m.authFunc(ctx, params)
	}
	return nil, nil
}

type mockSessionRepo struct {
	createFunc            func(ctx context.Context, session *repository.Session) error
	getByTokenHashFunc    func(ctx context.Context, tokenHash string) (*repository.Session, error)
	rotateFunc            func(ctx context.Context, oldTokenHash string, now time.Time, fn repository.RotateFn) (*repository.Session, error)
	revokeByTokenHashFunc func(ctx context.Context, tokenHash string, revokedAt time.Time) error

	created  []*repository.Session
	sessions map[string]*repository.Session
	history  map[string]*repository.Session
	users    map[uuid.UUID]repository.Status
	mu       sync.Mutex
}

func newMockSessionRepo() *mockSessionRepo {
	return &mockSessionRepo{
		sessions: make(map[string]*repository.Session),
		history:  make(map[string]*repository.Session),
		users:    make(map[uuid.UUID]repository.Status),
	}
}

func (m *mockSessionRepo) Create(ctx context.Context, session *repository.Session) error {
	if m.createFunc != nil {
		return m.createFunc(ctx, session)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.created = append(m.created, session)
	if m.sessions == nil {
		m.sessions = make(map[string]*repository.Session)
	}
	m.sessions[session.TokenHash] = session
	return nil
}

func (m *mockSessionRepo) GetByTokenHash(ctx context.Context, tokenHash string) (*repository.Session, error) {
	if m.getByTokenHashFunc != nil {
		return m.getByTokenHashFunc(ctx, tokenHash)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	sess, ok := m.sessions[tokenHash]
	if !ok {
		return nil, repository.ErrSessionNotFound
	}
	return sess, nil
}

func (m *mockSessionRepo) Rotate(ctx context.Context, oldTokenHash string, now time.Time, fn repository.RotateFn) (*repository.Session, error) {
	if m.rotateFunc != nil {
		return m.rotateFunc(ctx, oldTokenHash, now, fn)
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	sess, ok := m.sessions[oldTokenHash]
	if !ok {
		if m.history != nil {
			if histSess, found := m.history[oldTokenHash]; found {
				if histSess.RevokedAt == nil {
					rev := now
					histSess.RevokedAt = &rev
				}
				return nil, repository.ErrSessionRevoked
			}
		}
		return nil, repository.ErrSessionNotFound
	}

	uStatus, ok := m.users[sess.UserID]
	if !ok {
		uStatus = repository.StatusActive
	}

	newTokenHash, newExpiresAt, err := fn(sess, uStatus)
	if err != nil {
		return nil, err
	}

	if m.history == nil {
		m.history = make(map[string]*repository.Session)
	}
	m.history[oldTokenHash] = sess
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

func (m *mockSessionRepo) ListActiveByUserID(ctx context.Context, userID uuid.UUID, now time.Time) ([]repository.Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []repository.Session
	for _, s := range m.sessions {
		if s.UserID == userID && s.RevokedAt == nil && s.ExpiresAt.After(now) {
			out = append(out, *s)
		}
	}
	return out, nil
}

func (m *mockSessionRepo) RevokeByID(ctx context.Context, userID, sessionID uuid.UUID, revokedAt time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, s := range m.sessions {
		if s.ID == sessionID && s.UserID == userID {
			if s.RevokedAt == nil {
				rev := revokedAt
				s.RevokedAt = &rev
			}
			return nil
		}
	}
	return repository.ErrSessionNotFound
}

type mockTokenIssuer struct {
	issueFunc func(userID uuid.UUID, sessionID uuid.UUID, now time.Time) (accessToken, rawRefreshToken, tokenHash string, expiresIn time.Duration, err error)
}

func (m *mockTokenIssuer) Issue(userID uuid.UUID, sessionID uuid.UUID, now time.Time) (string, string, string, time.Duration, error) {
	if m.issueFunc != nil {
		return m.issueFunc(userID, sessionID, now)
	}
	return "mock_access_token", "mock_raw_refresh", repository.HashRefreshToken("mock_raw_refresh"), 15 * time.Minute, nil
}

func TestSession_HashAndVerify(t *testing.T) {
	token, err := repository.GenerateRefreshToken()
	if err != nil {
		t.Fatalf("GenerateRefreshToken failed: %v", err)
	}
	if len(token) != 64 { // 32 hex bytes = 64 characters
		t.Fatalf("expected 64 character hex string, got %d", len(token))
	}

	hash := repository.HashRefreshToken(token)
	if hash == token {
		t.Fatal("hash should never match raw token")
	}

	if !repository.VerifyRefreshToken(token, hash) {
		t.Fatal("VerifyRefreshToken failed for matching token and hash")
	}

	if repository.VerifyRefreshToken("wrong_token", hash) {
		t.Fatal("VerifyRefreshToken succeeded for mismatched token")
	}
}

func TestSessionService_Login_Success(t *testing.T) {
	userID := uuid.New()
	testUser := &repository.User{
		ID:          userID,
		Email:       "user@kr0n.dev",
		DisplayName: "User One",
		Status:      repository.StatusActive,
	}

	auth := &mockAuthenticator{
		authFunc: func(ctx context.Context, params service.AuthenticateParams) (*repository.User, error) {
			return testUser, nil
		},
	}
	repo := &mockSessionRepo{}
	signer := testSigner(t)
	issuer := service.NewDefaultTokenIssuer(signer)

	svc := service.NewSessionService(auth, repo, issuer, 30*24*time.Hour)

	ua := "Mozilla/5.0"
	clientIP := net.ParseIP("192.168.1.1")

	res, err := svc.Login(context.Background(), service.LoginParams{
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
	if !repository.VerifyRefreshToken(res.RefreshToken, createdSession.TokenHash) {
		t.Fatal("stored hash must verify against returned refresh token")
	}
	if createdSession.UserAgent == nil || *createdSession.UserAgent != ua {
		t.Fatal("session UserAgent mismatch")
	}
	if createdSession.IPAddress == nil || !createdSession.IPAddress.Equal(clientIP) {
		t.Fatal("session IPAddress mismatch")
	}
}

func TestSessionService_Login_InvalidCredentials(t *testing.T) {
	auth := &mockAuthenticator{
		authFunc: func(ctx context.Context, params service.AuthenticateParams) (*repository.User, error) {
			return nil, repository.ErrInvalidCredentials
		},
	}
	repo := &mockSessionRepo{}
	signer := testSigner(t)
	issuer := service.NewDefaultTokenIssuer(signer)

	svc := service.NewSessionService(auth, repo, issuer, 30*24*time.Hour)

	_, err := svc.Login(context.Background(), service.LoginParams{
		Email:    "unknown@kr0n.dev",
		Password: "wrong",
	})
	if !errors.Is(err, repository.ErrInvalidCredentials) {
		t.Fatalf("expected ErrInvalidCredentials, got %v", err)
	}

	if len(repo.created) != 0 {
		t.Fatal("expected no sessions created on failed authentication")
	}
}

func TestSessionService_Login_InactiveUser(t *testing.T) {
	auth := &mockAuthenticator{
		authFunc: func(ctx context.Context, params service.AuthenticateParams) (*repository.User, error) {
			return nil, repository.ErrUserNotActive
		},
	}
	repo := &mockSessionRepo{}
	signer := testSigner(t)
	issuer := service.NewDefaultTokenIssuer(signer)

	svc := service.NewSessionService(auth, repo, issuer, 30*24*time.Hour)

	_, err := svc.Login(context.Background(), service.LoginParams{
		Email:    "inactive@kr0n.dev",
		Password: "password123",
	})
	if !errors.Is(err, repository.ErrUserNotActive) {
		t.Fatalf("expected ErrUserNotActive, got %v", err)
	}

	if len(repo.created) != 0 {
		t.Fatal("expected no sessions created for inactive user")
	}
}

func TestSessionService_Login_TokenIssuerFailure(t *testing.T) {
	auth := &mockAuthenticator{
		authFunc: func(ctx context.Context, params service.AuthenticateParams) (*repository.User, error) {
			return &repository.User{ID: uuid.New(), Status: repository.StatusActive}, nil
		},
	}
	repo := &mockSessionRepo{}
	issuer := &mockTokenIssuer{
		issueFunc: func(userID uuid.UUID, sessionID uuid.UUID, now time.Time) (string, string, string, time.Duration, error) {
			return "", "", "", 0, errors.New("crypto entropy error")
		},
	}

	svc := service.NewSessionService(auth, repo, issuer, 30*24*time.Hour)

	_, err := svc.Login(context.Background(), service.LoginParams{
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

func TestSessionService_Login_SessionRepoFailure(t *testing.T) {
	auth := &mockAuthenticator{
		authFunc: func(ctx context.Context, params service.AuthenticateParams) (*repository.User, error) {
			return &repository.User{ID: uuid.New(), Status: repository.StatusActive}, nil
		},
	}
	repo := &mockSessionRepo{
		createFunc: func(ctx context.Context, session *repository.Session) error {
			return errors.New("db disk full")
		},
	}
	signer := testSigner(t)
	issuer := service.NewDefaultTokenIssuer(signer)

	svc := service.NewSessionService(auth, repo, issuer, 30*24*time.Hour)

	res, err := svc.Login(context.Background(), service.LoginParams{
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
		token, err := repository.GenerateRefreshToken()
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
	rawToken, _ := repository.GenerateRefreshToken()
	tokenHash := repository.HashRefreshToken(rawToken)

	sess := &repository.Session{
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
	newRawToken, _ := repository.GenerateRefreshToken()
	newTokenHash := repository.HashRefreshToken(newRawToken)
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
	expiredSess := &repository.Session{
		ID:        uuid.New(),
		UserID:    userID,
		TokenHash: tokenHash,
		ExpiresAt: now.Add(-1 * time.Hour),
	}
	if expiredSess.ExpiresAt.After(now) {
		t.Fatal("expected session to be expired")
	}
}

func TestSessionService_Refresh_Success(t *testing.T) {
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
	_, err = repo.GetByTokenHash(ctx, repository.HashRefreshToken(rawRefresh))
	if !errors.Is(err, repository.ErrSessionNotFound) {
		t.Fatalf("expected old token hash to be not found, got %v", err)
	}

	newSess, err := repo.GetByTokenHash(ctx, repository.HashRefreshToken(res.RefreshToken))
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

func TestSessionService_Refresh_InvalidToken(t *testing.T) {
	svc, _, _, _, _ := setupTestSessionService()
	ctx := context.Background()

	// Empty token
	_, err := svc.Refresh(ctx, "")
	if !errors.Is(err, repository.ErrInvalidRefreshToken) {
		t.Fatalf("expected ErrInvalidRefreshToken for empty token, got %v", err)
	}

	// Whitespace token
	_, err = svc.Refresh(ctx, "   ")
	if !errors.Is(err, repository.ErrInvalidRefreshToken) {
		t.Fatalf("expected ErrInvalidRefreshToken for whitespace token, got %v", err)
	}

	// Nonexistent token
	nonexistentToken, _ := repository.GenerateRefreshToken()
	_, err = svc.Refresh(ctx, nonexistentToken)
	if !errors.Is(err, repository.ErrInvalidRefreshToken) {
		t.Fatalf("expected ErrInvalidRefreshToken for nonexistent token, got %v", err)
	}
}

func TestSessionService_Refresh_ExpiredSession(t *testing.T) {
	svc, repo, _, rawRefresh, sess := setupTestSessionService()
	ctx := context.Background()

	// Expire the session in repo
	sess.ExpiresAt = time.Now().UTC().Add(-1 * time.Hour)
	repo.sessions[sess.TokenHash] = sess

	_, err := svc.Refresh(ctx, rawRefresh)
	if !errors.Is(err, repository.ErrSessionExpired) {
		t.Fatalf("expected ErrSessionExpired, got %v", err)
	}
}

func TestSessionService_Refresh_RevokedSession(t *testing.T) {
	svc, repo, _, rawRefresh, sess := setupTestSessionService()
	ctx := context.Background()

	// Revoke the session in repo
	revokedAt := time.Now().UTC()
	sess.RevokedAt = &revokedAt
	repo.sessions[sess.TokenHash] = sess

	_, err := svc.Refresh(ctx, rawRefresh)
	if !errors.Is(err, repository.ErrSessionRevoked) {
		t.Fatalf("expected ErrSessionRevoked, got %v", err)
	}
}

func TestSessionService_Refresh_InactiveUser(t *testing.T) {
	svc, repo, testUser, rawRefresh, _ := setupTestSessionService()
	ctx := context.Background()

	// Mark user as suspended
	repo.users[testUser.ID] = repository.StatusSuspended

	_, err := svc.Refresh(ctx, rawRefresh)
	if !errors.Is(err, repository.ErrUserNotActive) {
		t.Fatalf("expected ErrUserNotActive, got %v", err)
	}
}

func TestSessionService_Refresh_RotationCycle(t *testing.T) {
	svc, _, _, initialToken, sess := setupTestSessionService()
	ctx := context.Background()

	// 1. First refresh rotates initial token -> res1.RefreshToken
	res1, err := svc.Refresh(ctx, initialToken)
	if err != nil {
		t.Fatalf("first refresh failed: %v", err)
	}

	// 2. Second refresh with res1.RefreshToken rotates -> res2.RefreshToken
	res2, err := svc.Refresh(ctx, res1.RefreshToken)
	if err != nil {
		t.Fatalf("refresh with new rotated token failed: %v", err)
	}
	if res2.RefreshToken == res1.RefreshToken {
		t.Fatal("expected second rotation to produce another fresh token")
	}

	// 3. Reusing already-rotated initialToken triggers reuse detection and revokes the session!
	_, err = svc.Refresh(ctx, initialToken)
	if !errors.Is(err, repository.ErrSessionRevoked) {
		t.Fatalf("expected reused refresh token to revoke session with ErrSessionRevoked, got %v", err)
	}
	if sess.RevokedAt == nil {
		t.Fatal("expected session RevokedAt to be set upon token reuse detection")
	}

	// 4. Even the latest token (res2.RefreshToken) must now fail because the session was revoked
	_, err = svc.Refresh(ctx, res2.RefreshToken)
	if !errors.Is(err, repository.ErrSessionRevoked) {
		t.Fatalf("expected latest token to fail after reuse-triggered revocation, got %v", err)
	}
}

func TestSessionService_ListAndRevokeSessions(t *testing.T) {
	svc, _, testUser, _, sess := setupTestSessionService()
	ctx := context.Background()

	list, err := svc.ListSessions(ctx, testUser.ID)
	if err != nil {
		t.Fatalf("ListSessions: %v", err)
	}
	if len(list) != 1 || list[0].ID != sess.ID {
		t.Fatalf("expected 1 active session %s, got %+v", sess.ID, list)
	}

	// Revoke non-existent session
	if err := svc.RevokeSession(ctx, testUser.ID, uuid.New()); !errors.Is(err, repository.ErrSessionNotFound) {
		t.Fatalf("expected ErrSessionNotFound, got %v", err)
	}

	// Revoke existing session
	if err := svc.RevokeSession(ctx, testUser.ID, sess.ID); err != nil {
		t.Fatalf("RevokeSession: %v", err)
	}

	listAfter, err := svc.ListSessions(ctx, testUser.ID)
	if err != nil {
		t.Fatalf("ListSessions after revoke: %v", err)
	}
	if len(listAfter) != 0 {
		t.Fatalf("expected 0 active sessions after revoke, got %d", len(listAfter))
	}
}

func TestSessionService_Logout_RevokesSession(t *testing.T) {
	svc, repo, _, rawRefresh, sess := setupTestSessionService()
	ctx := context.Background()

	_, err := svc.Logout(ctx, rawRefresh)
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
	if !errors.Is(err, repository.ErrSessionRevoked) {
		t.Fatalf("expected ErrSessionRevoked after logout, got %v", err)
	}
}

func TestSessionService_Logout_SafeAndIdempotent(t *testing.T) {
	svc, _, _, rawRefresh, _ := setupTestSessionService()
	ctx := context.Background()

	// Logout with invalid token is safe/idempotent
	if _, err := svc.Logout(ctx, "invalid_random_token_123"); err != nil {
		t.Fatalf("expected nil on invalid token logout, got %v", err)
	}
	if _, err := svc.Logout(ctx, ""); err != nil {
		t.Fatalf("expected nil on empty token logout, got %v", err)
	}

	// Calling logout twice with valid token is idempotent
	if _, err := svc.Logout(ctx, rawRefresh); err != nil {
		t.Fatalf("first logout failed: %v", err)
	}
	if _, err := svc.Logout(ctx, rawRefresh); err != nil {
		t.Fatalf("second logout must be idempotent and succeed: %v", err)
	}
}

func TestSessionService_Refresh_ConcurrentRequestsPreventDoubleRotation(t *testing.T) {
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

func testSigner(t *testing.T) *jwtkeys.Signer {
	t.Helper()
	s, err := jwtkeys.NewSigner(jwtkeys.DevPrivateKey(), "k1", "kr0n-auth", "kr0n-api", 15*time.Minute)
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	return s
}

func setupTestSessionService() (*service.SessionService, *mockSessionRepo, *repository.User, string, *repository.Session) {
	userID := uuid.New()
	testUser := &repository.User{
		ID:          userID,
		Email:       "service_test@kr0n.dev",
		DisplayName: "Service Test User",
		Status:      repository.StatusActive,
	}

	auth := &mockAuthenticator{
		authFunc: func(ctx context.Context, params service.AuthenticateParams) (*repository.User, error) {
			return testUser, nil
		},
	}
	repo := newMockSessionRepo()
	repo.users[userID] = repository.StatusActive

	signer, _ := jwtkeys.NewSigner(jwtkeys.DevPrivateKey(), "k1", "kr0n-auth", "kr0n-api", 15*time.Minute)
	issuer := service.NewDefaultTokenIssuer(signer)
	svc := service.NewSessionService(auth, repo, issuer, 30*24*time.Hour)

	rawRefresh, _ := repository.GenerateRefreshToken()
	tokenHash := repository.HashRefreshToken(rawRefresh)
	now := time.Now().UTC()
	sess := &repository.Session{
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
