package session

import (
	"context"
	"errors"
	"net"
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
	createFunc func(ctx context.Context, session *Session) error
	created    []*Session
}

func (m *mockSessionRepo) Create(ctx context.Context, session *Session) error {
	if m.createFunc != nil {
		return m.createFunc(ctx, session)
	}
	m.created = append(m.created, session)
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
