package middleware

import (
	"net"
	"net/http/httptest"
	"testing"
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
