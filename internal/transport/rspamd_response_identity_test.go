package transport

import (
	"errors"
	"strings"
	"testing"

	"github.com/gigabytegrove/spamgate/internal/core"
)

func TestRspamdResponseIdentity(t *testing.T) {
	cases := []struct {
		name, id, messageID string
		valid bool
	}{
		{"normal", "scan_0123-ABC", "<id@example.test>", true},
		{"missing optional message ID", "scan_123", "", true},
		{"empty scan ID", "", "<id@example.test>", false},
		{"space scan ID", "scan 1", "", false},
		{"slash scan ID", "scan/1", "", false},
		{"newline scan ID", "scan\n1", "", false},
		{"oversize scan ID", strings.Repeat("a", rspamdMaxScanIDBytes+1), "", false},
		{"boundary scan ID", strings.Repeat("a", rspamdMaxScanIDBytes), "", true},
		{"message newline", "scan1", "<id\n@example.test>", false},
		{"message nul", "scan1", "<id\x00@example.test>", false},
		{"message delete", "scan1", "<id\x7f@example.test>", false},
		{"message C1", "scan1", "<id\u0085@example.test>", false},
		{"message invalid utf8", "scan1", string([]byte{0xff}), false},
		{"message oversize", "scan1", strings.Repeat("x", rspamdMaxMessageIDBytes+1), false},
		{"message boundary", "scan1", strings.Repeat("x", rspamdMaxMessageIDBytes), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := rspamdValidateResponseIdentity(core.Message{ID: tc.id, MessageID: tc.messageID})
			if tc.valid && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !tc.valid && !errors.Is(err, errRspamdResponseIdentity) {
				t.Fatalf("expected identity error, got %v", err)
			}
		})
	}
}
