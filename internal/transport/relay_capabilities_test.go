package transport

import (
	"strings"
	"testing"

	"github.com/gigabytegrove/spamgate/internal/core"
)

func TestRelayCapabilityRequirements(t *testing.T) {
	tests := []struct {
		name       string
		sender     string
		recipients []string
		raw        []byte
		want8bit   bool
		wantUTF8   bool
	}{
		{"ASCII original", "sender@example.invalid", []string{"recipient@example.invalid"}, []byte("Subject: test\r\n\r\nbody\r\n"), false, false},
		{"eight bit body", "sender@example.invalid", []string{"recipient@example.invalid"}, []byte("Subject: test\r\n\r\ncaf\xc3\xa9\r\n"), true, false},
		{"eight bit header", "sender@example.invalid", []string{"recipient@example.invalid"}, []byte("Subject: caf\xc3\xa9\r\n\r\nbody\r\n"), true, false},
		{"international recipient", "sender@example.invalid", []string{"b\xc3\xbcro@example.invalid"}, []byte("Subject: test\r\n\r\nbody\r\n"), false, true},
		{"international sender", "b\xc3\xbcro@example.invalid", []string{"recipient@example.invalid"}, []byte("Subject: test\r\n\r\nbody\r\n"), false, true},
		{"null reverse path", "<>", []string{"recipient@example.invalid"}, []byte("Subject: DSN\r\n\r\nbody\r\n"), false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := containsEightBit(tt.raw); got != tt.want8bit {
				t.Fatalf("8BITMIME required=%t, want %t", got, tt.want8bit)
			}
			m := core.Message{Sender: tt.sender, Recipients: tt.recipients}
			if got := requiresSMTPUTF8(m); got != tt.wantUTF8 {
				t.Fatalf("SMTPUTF8 required=%t, want %t", got, tt.wantUTF8)
			}
		})
	}
}

func TestNilRelayClientCannotBypassCapabilityChecks(t *testing.T) {
	if err := checkRelayCapabilities(nil, core.Message{}, nil); err == nil ||
		!strings.Contains(err.Error(), "nil") {
		t.Fatalf("nil client accepted: %v", err)
	}
}
