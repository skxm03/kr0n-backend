// Package jwtkeys signs and verifies kr0n access tokens with Ed25519 (JWS alg "EdDSA").
//
// The auth service holds the private key; the gateway holds only public keys, so a gateway
// compromise cannot mint tokens. Each key has a kid, which allows rotation: add the new public
// key to the gateway, switch the signer, and drop the old key once old tokens have expired.
package jwtkeys

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

var (
	// ErrInvalidToken means the token is malformed, uses a disallowed alg, or has a bad signature or claims.
	ErrInvalidToken = errors.New("invalid jwt token")
	// ErrTokenExpired means the token's exp is in the past.
	ErrTokenExpired = errors.New("jwt token expired")
)

const algEdDSA = "EdDSA"

type header struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	Kid string `json:"kid"`
}

// Claims are the access-token claims.
type Claims struct {
	Issuer    string `json:"iss"`
	Subject   string `json:"sub"`
	Audience  string `json:"aud"`
	SessionID string `json:"sid"`
	ID        string `json:"jti"`
	IssuedAt  int64  `json:"iat"`
	ExpiresAt int64  `json:"exp"`
}

// Signer issues EdDSA access tokens.
type Signer struct {
	key      ed25519.PrivateKey
	kid      string
	issuer   string
	audience string
	lifetime time.Duration
}

// NewSigner builds a Signer. kid, issuer and audience must be non-empty and lifetime positive.
func NewSigner(key ed25519.PrivateKey, kid, issuer, audience string, lifetime time.Duration) (*Signer, error) {
	switch {
	case len(key) != ed25519.PrivateKeySize:
		return nil, errors.New("jwtkeys: invalid ed25519 private key")
	case kid == "" || issuer == "" || audience == "":
		return nil, errors.New("jwtkeys: kid, issuer and audience are required")
	case lifetime <= 0:
		return nil, errors.New("jwtkeys: lifetime must be positive")
	}
	return &Signer{key: key, kid: kid, issuer: issuer, audience: audience, lifetime: lifetime}, nil
}

// Sign implements session.TokenSigner.
func (s *Signer) Sign(userID, sessionID uuid.UUID, now time.Time) (string, time.Duration, error) {
	h, err := json.Marshal(header{Alg: algEdDSA, Typ: "JWT", Kid: s.kid})
	if err != nil {
		return "", 0, err
	}
	c, err := json.Marshal(Claims{
		Issuer: s.issuer, Subject: userID.String(), Audience: s.audience,
		SessionID: sessionID.String(), ID: uuid.NewString(),
		IssuedAt: now.Unix(), ExpiresAt: now.Add(s.lifetime).Unix(),
	})
	if err != nil {
		return "", 0, err
	}
	enc := base64.RawURLEncoding
	signingInput := enc.EncodeToString(h) + "." + enc.EncodeToString(c)
	sig := ed25519.Sign(s.key, []byte(signingInput))
	return signingInput + "." + enc.EncodeToString(sig), s.lifetime, nil
}

// JWK represents an Ed25519 JSON Web Key (RFC 8037).
type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	X   string `json:"x"` // base64url-encoded 32-byte Ed25519 public key
}

// PublicJWK returns the RFC 8037 OKP JWK for this Signer's public key.
func (s *Signer) PublicJWK() JWK {
	return PublicKeyToJWK(s.kid, s.key.Public().(ed25519.PublicKey))
}

// PublicKeyToJWK formats an Ed25519 public key and kid as an OKP JWK.
func PublicKeyToJWK(kid string, pub ed25519.PublicKey) JWK {
	return JWK{
		Kty: "OKP",
		Crv: "Ed25519",
		Kid: kid,
		Alg: algEdDSA,
		Use: "sig",
		X:   base64.RawURLEncoding.EncodeToString(pub),
	}
}

// ParseJWK validates and extracts kid and ed25519.PublicKey from a JWK.
func ParseJWK(k JWK) (string, ed25519.PublicKey, error) {
	if k.Kty != "OKP" || k.Crv != "Ed25519" || (k.Alg != "" && k.Alg != algEdDSA) || k.Kid == "" {
		return "", nil, fmt.Errorf("jwtkeys: unsupported JWK metadata (kid=%q kty=%q crv=%q alg=%q)", k.Kid, k.Kty, k.Crv, k.Alg)
	}
	raw, err := base64.RawURLEncoding.DecodeString(k.X)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return "", nil, fmt.Errorf("jwtkeys: invalid JWK public key x for kid %q", k.Kid)
	}
	return k.Kid, ed25519.PublicKey(raw), nil
}

// KeySetProvider fetches the active public key set (e.g. over gRPC GetJWKS).
type KeySetProvider interface {
	FetchJWKS(ctx context.Context) ([]JWK, error)
}

// VerifierOption configures a Verifier.
type VerifierOption func(*Verifier)

// WithKeySetProvider configures a remote JWKS provider used to refresh keys on unknown kid.
func WithKeySetProvider(p KeySetProvider, minRefreshInterval time.Duration) VerifierOption {
	return func(v *Verifier) {
		v.provider = p
		if minRefreshInterval <= 0 {
			minRefreshInterval = 5 * time.Second
		}
		v.minRefreshInterval = minRefreshInterval
	}
}

// Verifier validates access tokens against a set of public keys.
type Verifier struct {
	mu                 sync.RWMutex
	keys               map[string]ed25519.PublicKey
	lastRefresh        time.Time
	minRefreshInterval time.Duration
	provider           KeySetProvider
	issuer             string
	audience           string
}

// NewVerifier builds a Verifier from kid → public key and optional dynamic KeySetProvider.
func NewVerifier(keys map[string]ed25519.PublicKey, issuer, audience string, opts ...VerifierOption) (*Verifier, error) {
	copied := make(map[string]ed25519.PublicKey, len(keys))
	for k, pub := range keys {
		copied[k] = pub
	}
	v := &Verifier{
		keys:               copied,
		issuer:             issuer,
		audience:           audience,
		minRefreshInterval: 5 * time.Second,
	}
	for _, opt := range opts {
		opt(v)
	}
	if len(v.keys) == 0 && v.provider == nil {
		return nil, errors.New("jwtkeys: at least one public key or a KeySetProvider is required")
	}
	return v, nil
}

// Verify checks alg (EdDSA only), kid, signature, issuer, audience and expiry.
// If the token's kid is unknown and a KeySetProvider is configured, Verify refreshes
// the key set (rate-limited by minRefreshInterval) before rejecting the token.
func (v *Verifier) Verify(token string, now time.Time) (*Claims, error) {
	return v.VerifyContext(context.Background(), token, now)
}

// VerifyContext is like Verify but passes ctx to the KeySetProvider when refreshing on an unknown kid.
func (v *Verifier) VerifyContext(ctx context.Context, token string, now time.Time) (*Claims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, ErrInvalidToken
	}
	enc := base64.RawURLEncoding
	hb, err := enc.DecodeString(parts[0])
	if err != nil {
		return nil, ErrInvalidToken
	}
	var h header
	if json.Unmarshal(hb, &h) != nil || h.Alg != algEdDSA || h.Kid == "" {
		return nil, ErrInvalidToken // rejects "none" and HS256 downgrade attempts
	}
	pub, ok := v.lookupKey(ctx, h.Kid, now)
	if !ok {
		return nil, ErrInvalidToken
	}
	sig, err := enc.DecodeString(parts[2])
	if err != nil || !ed25519.Verify(pub, []byte(parts[0]+"."+parts[1]), sig) {
		return nil, ErrInvalidToken
	}
	cb, err := enc.DecodeString(parts[1])
	if err != nil {
		return nil, ErrInvalidToken
	}
	var c Claims
	if json.Unmarshal(cb, &c) != nil || c.Issuer != v.issuer || c.Audience != v.audience || c.Subject == "" {
		return nil, ErrInvalidToken
	}
	if now.Unix() >= c.ExpiresAt {
		return nil, ErrTokenExpired
	}
	return &c, nil
}

func (v *Verifier) lookupKey(ctx context.Context, kid string, now time.Time) (ed25519.PublicKey, bool) {
	v.mu.RLock()
	pub, ok := v.keys[kid]
	v.mu.RUnlock()
	if ok || v.provider == nil {
		return pub, ok
	}

	v.mu.Lock()
	defer v.mu.Unlock()
	if pub, ok = v.keys[kid]; ok {
		return pub, true
	}
	if !v.lastRefresh.IsZero() && now.Sub(v.lastRefresh) < v.minRefreshInterval {
		return nil, false
	}
	v.lastRefresh = now

	rctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	jwks, err := v.provider.FetchJWKS(rctx)
	if err != nil {
		return nil, false
	}
	for _, jwk := range jwks {
		if k, parsed, err := ParseJWK(jwk); err == nil {
			v.keys[k] = parsed
		}
	}
	pub, ok = v.keys[kid]
	return pub, ok
}

// ParsePrivateKey decodes a base64 (std) 32-byte Ed25519 seed.
func ParsePrivateKey(b64 string) (ed25519.PrivateKey, error) {
	seed, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, errors.New("jwtkeys: private key must be a base64-encoded 32-byte seed")
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// ParsePublicKeys decodes "kid:base64pub,kid2:base64pub2".
func ParsePublicKeys(s string) (map[string]ed25519.PublicKey, error) {
	out := map[string]ed25519.PublicKey{}
	for _, item := range strings.Split(s, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		kid, raw, ok := strings.Cut(item, ":")
		if !ok || kid == "" {
			return nil, fmt.Errorf("jwtkeys: bad public key entry %q (want kid:base64)", item)
		}
		pub, err := base64.StdEncoding.DecodeString(raw)
		if err != nil || len(pub) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("jwtkeys: public key %q is not a base64 32-byte key", kid)
		}
		out[kid] = ed25519.PublicKey(pub)
	}
	if len(out) == 0 {
		return nil, errors.New("jwtkeys: no public keys provided")
	}
	return out, nil
}

// DevPrivateKey returns a fixed, publicly known key for local development only.
// Config refuses to use it when KR0N_ENV=production.
func DevPrivateKey() ed25519.PrivateKey {
	seed := sha256.Sum256([]byte("kr0n-dev-only-signing-key"))
	return ed25519.NewKeyFromSeed(seed[:])
}
