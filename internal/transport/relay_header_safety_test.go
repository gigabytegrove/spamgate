package transport

import (
	"strings"
	"testing"

	"github.com/gigabytegrove/spamgate/internal/core"
)

func TestRelayHeaderSMTPUTF8Requirements(t *testing.T) {
	tests := []struct {
		name string
		raw string
		need bool
		bad bool
	}{
		{"ASCII headers", "Subject: plain\r\n\r\nbody\r\n", false, false},
		{"eight bit body only", "Subject: plain\r\n\r\ncaf\xc3\xa9\r\n", false, false},
		{"eight bit invalid body is not an invalid header", "Subject: plain\r\n\r\n\xff\r\n", false, false},
		{"RFC 6532 subject", "Subject: caf\xc3\xa9\r\n\r\nbody\r\n", true, false},
		{"RFC 6532 folded header", "Subject: plain\r\n \xc3\xa9\r\n\r\nbody\r\n", true, false},
		{"LF separator", "Subject: caf\xc3\xa9\n\nbody\n", true, false},
		{"ASCII encoded-word header", "Subject: =?UTF-8?B?Y2Fmw6k=?=\r\n\r\nbody\r\n", false, false},
		{"malformed UTF8 header", "Subject: \xff\r\n\r\nbody\r\n", false, true},
		{"truncated UTF8 header", "Subject: \xc3\r\n\r\nbody\r\n", false, true},
		{"NUL header", "Subject: x\x00\r\n\r\nbody\r\n", false, true},
		{"no separator with UTF8", "Subject: caf\xc3\xa9", true, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := inspectRelayHeader([]byte(tt.raw))
			if (err != nil) != tt.bad || got != tt.need {
				t.Fatalf("inspectRelayHeader need=%t err=%v, want need=%t bad=%t", got, err, tt.need, tt.bad)
			}
		})
	}
}

func TestRelayEnvelopeRejectsUnsafePathsBeforeSMTP(t *testing.T) {
	for _, tt := range []struct {
		name string
		sender string
		recipients []string
		bad bool
	}{
		{"ordinary", "sender@example.invalid", []string{"to@example.invalid"}, false},
		{"DSN null sender", "<>", []string{"to@example.invalid"}, false},
		{"DSN empty sender", "", []string{"to@example.invalid"}, false},
		{"UTF8 recipient", "sender@example.invalid", []string{"b\xc3\xbcro@example.invalid"}, false},
		{"quoted local part", "\"a b\"@example.invalid", []string{"\"quoted local\"@example.invalid"}, false},
		{"parameter injection", "sender@example.invalid", []string{"to@example.invalid> SIZE=0"}, true},
		{"angle wrapped recipient", "sender@example.invalid", []string{"<to@example.invalid>"}, true},
		{"parameter injection with tab", "sender@example.invalid", []string{"to@example.invalid\tBODY=8BITMIME"}, true},
		{"multiple recipients in one path", "sender@example.invalid", []string{"a@example.invalid,b@example.invalid"}, true},
		{"no recipients", "sender@example.invalid", nil, true},
		{"empty recipient", "sender@example.invalid", []string{""}, true},
		{"NUL sender", "a\x00@example.invalid", []string{"to@example.invalid"}, true},
		{"CRLF recipient", "sender@example.invalid", []string{"to@example.invalid\r\nRCPT TO:<evil@example.invalid>"}, true},
		{"invalid UTF8 sender", "a\xff@example.invalid", []string{"to@example.invalid"}, true},
		{"invalid UTF8 recipient", "sender@example.invalid", []string{"a\xff@example.invalid"}, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			err := validateRelayEnvelope(core.Message{Sender: tt.sender, Recipients: tt.recipients})
			if (err != nil) != tt.bad {
				t.Fatalf("validateRelayEnvelope err=%v, want bad=%t", err, tt.bad)
			}
			if err != nil && strings.Contains(err.Error(), "evil@example.invalid") {
				t.Fatal("relay error leaked attacker-supplied path")
			}
		})
	}
}
