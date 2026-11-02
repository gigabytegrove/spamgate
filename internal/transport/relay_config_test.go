package transport

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/gigabytegrove/spamgate/internal/core"
)

func TestRelayConfigurationValidation(t *testing.T) {
	tests := []struct {
		name string
		relay *Relay
		want string
	}{
		{"nil", nil, "not configured"},
		{"missing host", &Relay{Address: ":25", TLSMode: "required"}, "host:port"},
		{"missing port", &Relay{Address: "relay.example:0", TLSMode: "required"}, "between"},
		{"port too large", &Relay{Address: "relay.example:65536", TLSMode: "required"}, "between"},
		{"named port", &Relay{Address: "relay.example:smtp", TLSMode: "required"}, "numeric"},
		{"hostname newline", &Relay{Address: "relay.example\r\n:25", TLSMode: "required"}, "hostname"},
		{"missing TLS mode", &Relay{Address: "relay.example:25"}, "TLS mode"},
		{"unknown TLS mode", &Relay{Address: "relay.example:25", TLSMode: "opportunistic"}, "TLS mode"},
		{"plaintext credentials", &Relay{Address: "127.0.0.1:25", TLSMode: "none", Username: "user", Password: "secret"}, "requires TLS"},
		{"password without username", &Relay{Address: "relay.example:587", TLSMode: "required", Password: "secret"}, "together"},
		{"username without password", &Relay{Address: "relay.example:587", TLSMode: "required", Username: "user"}, "together"},
		{"NUL username", &Relay{Address: "relay.example:587", TLSMode: "required", Username: "user\x00other", Password: "secret"}, "control"},
		{"CRLF password", &Relay{Address: "relay.example:587", TLSMode: "required", Username: "user", Password: "secret\r\n"}, "control"},
		{"valid unauthenticated local", &Relay{Address: "127.0.0.1:25", TLSMode: "none"}, ""},
		{"valid STARTTLS auth", &Relay{Address: "relay.example:587", TLSMode: "required", Username: "user", Password: "secret"}, ""},
		{"valid implicit TLS auth", &Relay{Address: "relay.example:465", TLSMode: "implicit", Username: "user", Password: "secret"}, ""},
		{"valid bracketed IPv6", &Relay{Address: "[::1]:25", TLSMode: "none"}, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.relay.validateConfiguration()
			if tc.want == "" {
				if err != nil { t.Fatalf("valid relay rejected: %v", err) }
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("wanted error containing %q, got %v", tc.want, err)
			}
			if err != nil && strings.Contains(err.Error(), "secret") {
				t.Fatalf("credential leaked into error: %v", err)
			}
		})
	}
}

func TestRelayFromEnvRejectsIncompleteAndPlaintextCredentials(t *testing.T) {
	tests := []struct {
		name, mode, username, password, want string
	}{
		{"plaintext", "none", "user", "secret", "requires TLS"},
		{"missing password", "required", "user", "", "together"},
		{"missing username", "implicit", "", "secret", "together"},
		{"valid STARTTLS", "required", "user", "secret", ""},
		{"valid no auth", "none", "", "", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("SPAMGATE_RELAY_ADDRESS", "relay.example:587")
			t.Setenv("SPAMGATE_RELAY_TLS", tc.mode)
			t.Setenv("SPAMGATE_RELAY_USERNAME", tc.username)
			t.Setenv("SPAMGATE_RELAY_PASSWORD", tc.password)
			r, err := RelayFromEnv()
			if tc.want == "" {
				if err != nil || r == nil { t.Fatalf("expected valid relay: %v", err) }
				return
			}
			if r != nil || err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected refusal containing %q, relay=%v error=%v", tc.want, r != nil, err)
			}
		})
	}
}

func TestRelaySendRejectsUnsafeAuthenticationBeforeDial(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil { t.Fatal(err) }
	defer listener.Close()
	if err := listener.(*net.TCPListener).SetDeadline(time.Now().Add(200 * time.Millisecond)); err != nil { t.Fatal(err) }
	r := &Relay{Address: listener.Addr().String(), TLSMode: "none", Username: "user", Password: "secret"}
	err = r.Send(context.Background(), core.Message{Sender: "a@example.org", Recipients: []string{"b@example.org"}}, []byte("Subject: test\r\n\r\nbody\r\n"))
	if err == nil || !strings.Contains(err.Error(), "requires TLS") { t.Fatalf("unsafe send not refused: %v", err) }
	conn, err := listener.Accept()
	if err == nil {
		_ = conn.Close()
		t.Fatal("invalid relay opened TCP connection before rejecting credentials")
	}
	if ne, ok := err.(net.Error); !ok || !ne.Timeout() {
		t.Fatalf("unexpected accept error: %v", err)
	}
}
