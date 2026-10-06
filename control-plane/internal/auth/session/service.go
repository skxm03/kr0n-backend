package session

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/google/uuid"
	"github.com/skxm03/kr0n-backend/control-plane/internal/auth/user"
)

// TokenSigner defines the contract for generating signed access tokens.
type TokenSigner interface {
	Sign(userID uuid.UUID, sessionID uuid.UUID, now time.Time) (token string, expiresIn time.Duration, err error)
}

// TokenIssuer generates and packages access and refresh tokens.
type TokenIssuer interface {
	Issue(userID uuid.UUID, sessionID uuid.UUID, now time.Time) (accessToken, rawRefreshToken, tokenHash string, expiresIn time.Duration, err error)
}

// DefaultTokenIssuer issues an HMAC-SHA256 JWT access token and secure random opaque refresh token.
type DefaultTokenIssuer struct {
	signer TokenSigner
}

// NewDefaultTokenIssuer creates a DefaultTokenIssuer.
func NewDefaultTokenIssuer(signer TokenSigner) *DefaultTokenIssuer {
	return &DefaultTokenIssuer{signer: signer}
}

// Issue generates an access token and an opaque refresh token with its SHA-256 hash.
func (i *DefaultTokenIssuer) Issue(userID uuid.UUID, sessionID uuid.UUID, now time.Time) (string, string, string, time.Duration, error) {
	accessToken, expiresIn, err := i.signer.Sign(userID, sessionID, now)
	if err != nil {
		return "", "", "", 0, fmt.Errorf("sign access token: %w", err)
	}

	rawRefreshToken, err := GenerateRefreshToken()
	if err != nil {
		return "", "", "", 0, fmt.Errorf("generate refresh token: %w", err)
	}

	tokenHash := HashRefreshToken(rawRefreshToken)
	return accessToken, rawRefreshToken, tokenHash, expiresIn, nil
}

// Authenticator defines the contract for validating user credentials.
type Authenticator interface {
	Authenticate(ctx context.Context, params user.AuthenticateParams) (*user.User, error)
}

// Service orchestrates login authentication and session creation.
type Service struct {
	auth            Authenticator
	sessionRepo     Repository
	tokenIssuer     TokenIssuer
	sessionLifetime time.Duration
}

// NewService creates a session Service instance.
func NewService(auth Authenticator, sessionRepo Repository, tokenIssuer TokenIssuer, sessionLifetime time.Duration) *Service {
	if sessionLifetime <= 0 {
		sessionLifetime = 30 * 24 * time.Hour // default 30 days
	}
	return &Service{
		auth:            auth,
		sessionRepo:     sessionRepo,
		tokenIssuer:     tokenIssuer,
		sessionLifetime: sessionLifetime,
	}
}

// LoginParams contains parameters for the login operation.
type LoginParams struct {
	Email     string
	Password  string
	UserAgent *string
	ClientIP  *net.IP
}

// LoginResult contains the output of a successful login authentication.
type LoginResult struct {
	AccessToken  string
	RefreshToken string
	TokenType    string
	ExpiresIn    time.Duration
	User         *user.User
	SessionID    uuid.UUID
}

// Login authenticates credentials, creates a session, and issues tokens atomically.
func (s *Service) Login(ctx context.Context, params LoginParams) (*LoginResult, error) {
	// 1. Authenticate user credentials
	authenticatedUser, err := s.auth.Authenticate(ctx, user.AuthenticateParams{
		Email:    params.Email,
		Password: params.Password,
	})
	if err != nil {
		return nil, err
	}

	// 2. Prepare session identity and timestamps
	sessionID := uuid.New()
	now := time.Now().UTC()
	expiresAt := now.Add(s.sessionLifetime)

	// 3. Generate tokens BEFORE persisting session
	accessToken, rawRefreshToken, tokenHash, expiresIn, err := s.tokenIssuer.Issue(authenticatedUser.ID, sessionID, now)
	if err != nil {
		return nil, fmt.Errorf("issue tokens: %w", err)
	}

	// 4. Persist session with refresh token hash atomically
	sessionRecord := &Session{
		ID:         sessionID,
		UserID:     authenticatedUser.ID,
		TokenHash:  tokenHash,
		UserAgent:  params.UserAgent,
		IPAddress:  params.ClientIP,
		ExpiresAt:  expiresAt,
		RevokedAt:  nil,
		CreatedAt:  now,
		LastSeenAt: now,
	}

	if err := s.sessionRepo.Create(ctx, sessionRecord); err != nil {
		return nil, fmt.Errorf("persist session: %w", err)
	}

	return &LoginResult{
		AccessToken:  accessToken,
		RefreshToken: rawRefreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    expiresIn,
		User:         authenticatedUser,
		SessionID:    sessionID,
	}, nil
}
