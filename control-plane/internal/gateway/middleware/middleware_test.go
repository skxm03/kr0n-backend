package middleware

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/skxm03/kr0n-backend/control-plane/internal/auth/jwtkeys"
)

func TestClientIP(t *testing.T) {
	_, lb, _ := net.ParseCIDR("10.0.0.0/8")
	trusted := []*net.IPNet{lb}

	cases := []struct {
		name, remote, xff, want string
		trusted                 []*net.IPNet
	}{
		{"no proxies configured ignores XFF", "1.2.3.4:5000", "9.9.9.9", "1.2.3.4", nil},
		{"untrusted peer cannot spoof XFF", "1.2.3.4:5000", "9.9.9.9", "1.2.3.4", trusted},
		{"trusted proxy: client from XFF", "10.0.0.1:5000", "7.7.7.7", "7.7.7.7", trusted},
		{"spoofed leftmost entry ignored", "10.0.0.1:5000", "6.6.6.6, 7.7.7.7", "7.7.7.7", trusted},
		{"chain of our proxies skipped", "10.0.0.1:5000", "7.7.7.7, 10.0.0.2", "7.7.7.7", trusted},
		{"trusted peer without XFF", "10.0.0.1:5000", "", "10.0.0.1", trusted},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/", nil)
			r.RemoteAddr = c.remote
			if c.xff != "" {
				r.Header.Set("X-Forwarded-For", c.xff)
			}
			if got := ClientIP(r, c.trusted); got != c.want {
				t.Fatalf("got %s want %s", got, c.want)
			}
		})
	}
}

type testTokenVerifier struct {
	token  string
	claims *jwtkeys.Claims
	err    error
}

func (m *testTokenVerifier) VerifyContext(ctx context.Context, token string, now time.Time) (*jwtkeys.Claims, error) {
	m.token = token
	if m.err != nil {
		return nil, m.err
	}
	return m.claims, nil
}

func TestAuthenticate_CookieSupport(t *testing.T) {
	verifier := &testTokenVerifier{
		claims: &jwtkeys.Claims{
			Subject:   "u-cookie-user",
			SessionID: "s-12345",
		},
	}

	mw := Authenticate(verifier)
	var authenticatedPrincipal *Principal
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, ok := PrincipalFromContext(r.Context())
		if ok {
			authenticatedPrincipal = p
		}
		w.WriteHeader(http.StatusOK)
	}))

	t.Run("authenticates via access_token cookie when Authorization header is absent", func(t *testing.T) {
		authenticatedPrincipal = nil
		req := httptest.NewRequest(http.MethodGet, "/api/v1/me", nil)
		req.AddCookie(&http.Cookie{
			Name:  "access_token",
			Value: "jwt-cookie-token",
		})
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200 OK, got %d", rec.Code)
		}
		if verifier.token != "jwt-cookie-token" {
			t.Fatalf("expected verifier to receive cookie token, got %q", verifier.token)
		}
		if authenticatedPrincipal == nil || authenticatedPrincipal.UserID != "u-cookie-user" {
			t.Fatalf("unexpected principal: %+v", authenticatedPrincipal)
		}
	})

	t.Run("returns 401 when neither Authorization header nor cookie is present", func(t *testing.T) {
		authenticatedPrincipal = nil
		req := httptest.NewRequest(http.MethodGet, "/api/v1/me", nil)
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 Unauthorized, got %d", rec.Code)
		}
		if authenticatedPrincipal != nil {
			t.Fatalf("expected no principal, got %+v", authenticatedPrincipal)
		}
	})
}
