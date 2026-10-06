package session

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

var (
	// ErrInvalidSignerKey indicates the JWT secret key is too short or empty.
	ErrInvalidSignerKey = errors.New("jwt secret key must be at least 32 bytes")
	// ErrInvalidIssuer indicates an empty issuer configuration.
	ErrInvalidIssuer = errors.New("jwt issuer must not be empty")
	// ErrInvalidLifetime indicates non-positive token duration.
	ErrInvalidLifetime = errors.New("jwt expiration duration must be positive")
	// ErrInvalidToken indicates the token format or signature is invalid.
	ErrInvalidToken = errors.New("invalid jwt token")
	// ErrTokenExpired indicates the token exp timestamp is in the past.
	ErrTokenExpired = errors.New("jwt token expired")
)

// JWTHeader represents the header of an HMAC-SHA256 JWT.
type JWTHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
}

// JWTClaims represents standard claims for kr0n access tokens.
type JWTClaims struct {
	Issuer    string `json:"iss"`
	Subject   string `json:"sub"`
	SessionID string `json:"sid"`
	IssuedAt  int64  `json:"iat"`
	ExpiresAt int64  `json:"exp"`
}

// JWTSigner creates and validates HMAC-SHA256 signed access tokens.
type JWTSigner struct {
	secretKey []byte
	issuer    string
	lifetime  time.Duration
}

// NewJWTSigner creates a configured JWTSigner.
// secretKey must be at least 32 bytes for HMAC-SHA256 security.
func NewJWTSigner(secretKey []byte, issuer string, lifetime time.Duration) (*JWTSigner, error) {
	if len(secretKey) < 32 {
		return nil, ErrInvalidSignerKey
	}
	if strings.TrimSpace(issuer) == "" {
		return nil, ErrInvalidIssuer
	}
	if lifetime <= 0 {
		return nil, ErrInvalidLifetime
	}

	return &JWTSigner{
		secretKey: secretKey,
		issuer:    issuer,
		lifetime:  lifetime,
	}, nil
}

// Sign creates an HMAC-SHA256 JWT containing sub, sid, iss, iat, exp claims.
func (s *JWTSigner) Sign(userID uuid.UUID, sessionID uuid.UUID, now time.Time) (string, time.Duration, error) {
	header := JWTHeader{
		Alg: "HS256",
		Typ: "JWT",
	}

	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", 0, fmt.Errorf("marshal header: %w", err)
	}

	claims := JWTClaims{
		Issuer:    s.issuer,
		Subject:   userID.String(),
		SessionID: sessionID.String(),
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(s.lifetime).Unix(),
	}

	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", 0, fmt.Errorf("marshal claims: %w", err)
	}

	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	claimsB64 := base64.RawURLEncoding.EncodeToString(claimsJSON)

	payload := headerB64 + "." + claimsB64
	signature := s.computeHMAC([]byte(payload))
	sigB64 := base64.RawURLEncoding.EncodeToString(signature)

	return payload + "." + sigB64, s.lifetime, nil
}

// Verify decodes and validates the signature and expiration of an access token.
func (s *JWTSigner) Verify(tokenString string, now time.Time) (*JWTClaims, error) {
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil, ErrInvalidToken
	}

	payload := parts[0] + "." + parts[1]
	expectedSig := s.computeHMAC([]byte(payload))

	sigBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, ErrInvalidToken
	}

	if !hmac.Equal(expectedSig, sigBytes) {
		return nil, ErrInvalidToken
	}

	claimsBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, ErrInvalidToken
	}

	var claims JWTClaims
	if err := json.Unmarshal(claimsBytes, &claims); err != nil {
		return nil, ErrInvalidToken
	}

	if now.Unix() > claims.ExpiresAt {
		return nil, ErrTokenExpired
	}

	return &claims, nil
}

func (s *JWTSigner) computeHMAC(data []byte) []byte {
	mac := hmac.New(sha256.New, s.secretKey)
	mac.Write(data)
	return mac.Sum(nil)
}
