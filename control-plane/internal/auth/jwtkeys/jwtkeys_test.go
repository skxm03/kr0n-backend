package jwtkeys

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
)

func newPair(t *testing.T) (*Signer, *Verifier, ed25519.PublicKey) {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(nil)
	s, err := NewSigner(priv, "k1", "kr0n-auth", "kr0n-api", 15*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	v, err := NewVerifier(map[string]ed25519.PublicKey{"k1": pub}, "kr0n-auth", "kr0n-api")
	if err != nil {
		t.Fatal(err)
	}
	return s, v, pub
}

func TestSignVerifyRoundTrip(t *testing.T) {
	s, v, _ := newPair(t)
	uid, sid := uuid.New(), uuid.New()
	now := time.Now()
	tok, exp, err := s.Sign(uid, sid, now)
	if err != nil || exp != 15*time.Minute {
		t.Fatalf("sign: %v %v", exp, err)
	}
	c, err := v.Verify(tok, now)
	if err != nil {
		t.Fatal(err)
	}
	if c.Subject != uid.String() || c.SessionID != sid.String() || c.ID == "" {
		t.Fatalf("bad claims %+v", c)
	}
}

func TestVerifyRejects(t *testing.T) {
	s, v, _ := newPair(t)
	now := time.Now()
	tok, _, _ := s.Sign(uuid.New(), uuid.New(), now)

	if _, err := v.Verify(tok, now.Add(16*time.Minute)); !errors.Is(err, ErrTokenExpired) {
		t.Fatalf("expired: %v", err)
	}
	if _, err := v.Verify(tok+"x", now); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("tampered sig: %v", err)
	}

	parts := strings.Split(tok, ".")
	none := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT","kid":"k1"}`))
	if _, err := v.Verify(none+"."+parts[1]+".", now); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("alg none: %v", err)
	}

	// token signed by a different key but claiming kid k1
	_, other, _ := ed25519.GenerateKey(nil)
	rogue, _ := NewSigner(other, "k1", "kr0n-auth", "kr0n-api", time.Minute)
	rt, _, _ := rogue.Sign(uuid.New(), uuid.New(), now)
	if _, err := v.Verify(rt, now); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("forged: %v", err)
	}

	// wrong audience / unknown kid
	_, priv, _ := ed25519.GenerateKey(nil)
	wa, _ := NewSigner(priv, "k1", "kr0n-auth", "someone-else", time.Minute)
	_ = wa
	uk, _ := NewSigner(priv, "k2", "kr0n-auth", "kr0n-api", time.Minute)
	ut, _, _ := uk.Sign(uuid.New(), uuid.New(), now)
	if _, err := v.Verify(ut, now); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("unknown kid: %v", err)
	}
}

func TestVerifyWrongAudience(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	s, _ := NewSigner(priv, "k1", "kr0n-auth", "other", time.Minute)
	v, _ := NewVerifier(map[string]ed25519.PublicKey{"k1": pub}, "kr0n-auth", "kr0n-api")
	tok, _, _ := s.Sign(uuid.New(), uuid.New(), time.Now())
	if _, err := v.Verify(tok, time.Now()); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("got %v", err)
	}
}

func TestKeyParsing(t *testing.T) {
	seed := make([]byte, 32)
	priv, err := ParsePrivateKey(base64.StdEncoding.EncodeToString(seed))
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.Public().(ed25519.PublicKey)
	keys, err := ParsePublicKeys("a:" + base64.StdEncoding.EncodeToString(pub))
	if err != nil || len(keys["a"]) != 32 {
		t.Fatalf("%v %v", keys, err)
	}
	if _, err := ParsePrivateKey("short"); err == nil {
		t.Fatal("expected error")
	}
	if _, err := ParsePublicKeys("nocolon"); err == nil {
		t.Fatal("expected error")
	}
}

type fakeJWKSProvider struct {
	calls atomic.Int32
	keys  []JWK
	err   error
}

func (f *fakeJWKSProvider) FetchJWKS(_ context.Context) ([]JWK, error) {
	f.calls.Add(1)
	return f.keys, f.err
}

func TestVerifierJWKSRefreshAndRotation(t *testing.T) {
	_, priv1, _ := ed25519.GenerateKey(nil)
	s1, _ := NewSigner(priv1, "k1", "kr0n-auth", "kr0n-api", 15*time.Minute)
	_, priv2, _ := ed25519.GenerateKey(nil)
	s2, _ := NewSigner(priv2, "k2", "kr0n-auth", "kr0n-api", 15*time.Minute)

	provider := &fakeJWKSProvider{
		keys: []JWK{s1.PublicJWK(), s2.PublicJWK()},
	}

	// Start with empty local keys; must fetch k1 on first Verify
	v, err := NewVerifier(nil, "kr0n-auth", "kr0n-api", WithKeySetProvider(provider, 10*time.Second))
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now()
	tok1, _, _ := s1.Sign(uuid.New(), uuid.New(), now)
	if _, err := v.Verify(tok1, now); err != nil {
		t.Fatalf("expected k1 verified after JWKS refresh: %v", err)
	}
	if provider.calls.Load() != 1 {
		t.Fatalf("expected 1 JWKS fetch, got %d", provider.calls.Load())
	}

	// k2 was returned in the same JWKS response, so it should verify without another RPC
	tok2, _, _ := s2.Sign(uuid.New(), uuid.New(), now)
	if _, err := v.Verify(tok2, now); err != nil {
		t.Fatalf("expected k2 cached from first fetch: %v", err)
	}
	if provider.calls.Load() != 1 {
		t.Fatalf("expected cached k2 (still 1 fetch), got %d", provider.calls.Load())
	}

	// Unknown kid within minRefreshInterval is rejected without hammering provider
	_, priv3, _ := ed25519.GenerateKey(nil)
	s3, _ := NewSigner(priv3, "k3", "kr0n-auth", "kr0n-api", 15*time.Minute)
	provider.keys = append(provider.keys, s3.PublicJWK())
	tok3, _, _ := s3.Sign(uuid.New(), uuid.New(), now)
	if _, err := v.Verify(tok3, now.Add(2*time.Second)); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("expected rate-limited refresh to skip fetch and reject k3, got %v", err)
	}
	if provider.calls.Load() != 1 {
		t.Fatalf("expected no extra fetch during cooldown, got %d", provider.calls.Load())
	}

	// Past minRefreshInterval, k3 triggers a refresh and succeeds
	if _, err := v.Verify(tok3, now.Add(11*time.Second)); err != nil {
		t.Fatalf("expected k3 verified after cooldown elapsed: %v", err)
	}
	if provider.calls.Load() != 2 {
		t.Fatalf("expected 2nd fetch after cooldown, got %d", provider.calls.Load())
	}
}
