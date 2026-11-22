package transport

import (
	"strings"
	"testing"
)

func TestSMTPAuthorizationLocalPartBoundary(t *testing.T) {
	gateway := &SMTP{Domains: []string{"example.org"}}
	tests := []struct {
		name, address string
		want bool
	}{
		{"ordinary", "Alice@example.org", true},
		{"plus tag", "Alice+alerts@example.org", true},
		{"quoted", "\"alice smith\"@example.org", true},
		{"max local length", strings.Repeat("a", 64) + "@example.org", true},
		{"too long local", strings.Repeat("a", 65) + "@example.org", false},
		{"newline", "alice\nother@example.org", false},
		{"carriage return", "alice\rother@example.org", false},
		{"null", "alice\x00other@example.org", false},
		{"tab", "alice\tother@example.org", false},
		{"delete", "alice\x7fother@example.org", false},
		{"left angle", "alice<other@example.org", false},
		{"right angle", "alice>other@example.org", false},
		{"empty local", "@example.org", false},
		{"unauthorized domain", "alice@not-example.org", false},
		{"unicode domain", "alice@K.example.org", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := gateway.allowedRecipient(tc.address); got != tc.want {
				t.Errorf("allowedRecipient(%q) = %v; want %v", tc.address, got, tc.want)
			}
		})
	}
}

func TestSMTPAuthorizationLocalPartNeverNormalizes(t *testing.T) {
	gateway := &SMTP{Domains: []string{"example.org"}}
	for _, address := range []string{"Alice@example.org", "alice@example.org", "alice+tag@example.org"} {
		if !gateway.allowedRecipient(address) {
			t.Fatalf("valid mailbox denied: %q", address)
		}
	}
}
