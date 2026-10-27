package service

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/skxm03/kr0n-backend/control-plane/internal/auth/repository"
)

// TokenSigner defines the contract for generating signed access tokens.
type TokenSigner interface {
	Sign(userID uuid.UUID, sessionID uuid.UUID, now time.Time) (token string, expiresIn time.Duration, err error)
}

// TokenIssuer generates and packages access and refresh tokens.
type TokenIssuer interface {
	Issue(userID uuid.UUID, sessionID uuid.UUID, now time.Time) (accessToken, rawRefreshToken, tokenHash string, expiresIn time.Duration, err error)
}

// DefaultTokenIssuer issues a signed JWT access token and secure random opaque refresh token.
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

	rawRefreshToken, err := repository.GenerateRefreshToken()
	if err != nil {
		return "", "", "", 0, fmt.Errorf("generate refresh token: %w", err)
	}

	tokenHash := repository.HashRefreshToken(rawRefreshToken)
	return accessToken, rawRefreshToken, tokenHash, expiresIn, nil
}

// Authenticator defines the contract for validating user credentials.
type Authenticator interface {
	Authenticate(ctx context.Context, params AuthenticateParams) (*repository.User, error)
}

// SessionService orchestrates login authentication and session creation.
type SessionService struct {
	auth            Authenticator
	sessionRepo     repository.SessionRepository
	tokenIssuer     TokenIssuer
	sessionLifetime time.Duration
}

// NewSessionService creates a SessionService instance.
func NewSessionService(auth Authenticator, sessionRepo repository.SessionRepository, tokenIssuer TokenIssuer, sessionLifetime time.Duration) *SessionService {
	if sessionLifetime <= 0 {
		sessionLifetime = 30 * 24 * time.Hour // default 30 days
	}
	return &SessionService{
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
	User         *repository.User
	SessionID    uuid.UUID
}

// Login authenticates credentials, creates a session, and issues tokens atomically.
func (s *SessionService) Login(ctx context.Context, params LoginParams) (*LoginResult, error) {
	authenticatedUser, err := s.auth.Authenticate(ctx, AuthenticateParams{
		Email:    params.Email,
		Password: params.Password,
	})
	if err != nil {
		return nil, err
	}

	return s.CreateSessionForUser(ctx, authenticatedUser, params.UserAgent, params.ClientIP)
}

// CreateSessionForUser issues an access token and refresh token and persists the session for an already-authenticated user.
func (s *SessionService) CreateSessionForUser(ctx context.Context, authenticatedUser *repository.User, userAgent *string, clientIP *net.IP) (*LoginResult, error) {
	if authenticatedUser == nil {
		return nil, repository.ErrUserNotFound
	}
	if authenticatedUser.Status != repository.StatusActive {
		return nil, repository.ErrUserNotActive
	}

	sessionID, err := uuid.NewV7()
	if err != nil {
		sessionID = uuid.New()
	}
	now := time.Now().UTC()
	expiresAt := now.Add(s.sessionLifetime)

	accessToken, rawRefreshToken, tokenHash, expiresIn, err := s.tokenIssuer.Issue(authenticatedUser.ID, sessionID, now)
	if err != nil {
		return nil, fmt.Errorf("issue tokens: %w", err)
	}

	sessionRecord := &repository.Session{
		ID:         sessionID,
		UserID:     authenticatedUser.ID,
		TokenHash:  tokenHash,
		UserAgent:  userAgent,
		IPAddress:  clientIP,
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

// RefreshResult contains the output of a successful refresh token rotation.
type RefreshResult struct {
	AccessToken  string
	RefreshToken string
	TokenType    string
	ExpiresIn    time.Duration
}

// Refresh validates the supplied raw refresh token, atomically rotates it, and returns new tokens.
func (s *SessionService) Refresh(ctx context.Context, rawRefreshToken string) (*RefreshResult, error) {
	if strings.TrimSpace(rawRefreshToken) == "" {
		return nil, repository.ErrInvalidRefreshToken
	}

	oldTokenHash := repository.HashRefreshToken(rawRefreshToken)
	now := time.Now().UTC()
	newExpiresAt := now.Add(s.sessionLifetime)

	var (
		newAccessToken string
		newRawRefresh  string
		expiresIn      time.Duration
	)

	_, err := s.sessionRepo.Rotate(ctx, oldTokenHash, now, func(sess *repository.Session, userStatus repository.Status) (string, time.Time, error) {
		if sess.RevokedAt != nil {
			return "", time.Time{}, repository.ErrSessionRevoked
		}
		if !sess.ExpiresAt.After(now) {
			return "", time.Time{}, repository.ErrSessionExpired
		}
		if userStatus != repository.StatusActive {
			return "", time.Time{}, repository.ErrUserNotActive
		}

		accToken, rawRefresh, tokHash, exp, err := s.tokenIssuer.Issue(sess.UserID, sess.ID, now)
		if err != nil {
			return "", time.Time{}, fmt.Errorf("issue new tokens: %w", err)
		}

		newAccessToken = accToken
		newRawRefresh = rawRefresh
		expiresIn = exp

		return tokHash, newExpiresAt, nil
	})
	if err != nil {
		if errors.Is(err, repository.ErrSessionNotFound) {
			return nil, repository.ErrInvalidRefreshToken
		}
		return nil, err
	}

	return &RefreshResult{
		AccessToken:  newAccessToken,
		RefreshToken: newRawRefresh,
		TokenType:    "Bearer",
		ExpiresIn:    expiresIn,
	}, nil
}

// Logout revokes the session associated with the supplied refresh token.
func (s *SessionService) Logout(ctx context.Context, rawRefreshToken string) (*repository.Session, error) {
	if strings.TrimSpace(rawRefreshToken) == "" {
		return nil, nil
	}

	tokenHash := repository.HashRefreshToken(rawRefreshToken)
	now := time.Now().UTC()

	sess, _ := s.sessionRepo.GetByTokenHash(ctx, tokenHash)
	if err := s.sessionRepo.RevokeByTokenHash(ctx, tokenHash, now); err != nil {
		return nil, fmt.Errorf("revoke session: %w", err)
	}

	return sess, nil
}

// ListSessions returns all active (non-revoked, non-expired) sessions for a user.
func (s *SessionService) ListSessions(ctx context.Context, userID uuid.UUID) ([]repository.Session, error) {
	if userID == uuid.Nil {
		return nil, repository.ErrSessionNotFound
	}
	return s.sessionRepo.ListActiveByUserID(ctx, userID, time.Now().UTC())
}

// RevokeSession revokes a single session owned by userID.
func (s *SessionService) RevokeSession(ctx context.Context, userID, sessionID uuid.UUID) error {
	if userID == uuid.Nil || sessionID == uuid.Nil {
		return repository.ErrSessionNotFound
	}
	return s.sessionRepo.RevokeByID(ctx, userID, sessionID, time.Now().UTC())
}
