package gateway

import (
	"testing"
)

func TestDialUpstreamInsecure(t *testing.T) {
	conn, err := DialUpstream("127.0.0.1:50053", DialUpstreamTLSConfig{
		Insecure: true,
	}, "test-token")
	if err != nil {
		t.Fatalf("unexpected error creating insecure client connection: %v", err)
	}
	defer conn.Close()

	if conn.Target() != "127.0.0.1:50053" {
		t.Errorf("expected target 127.0.0.1:50053, got %s", conn.Target())
	}
}
