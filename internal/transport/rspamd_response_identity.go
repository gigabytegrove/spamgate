package transport

import (
	"errors"
	"unicode/utf8"

	"github.com/gigabytegrove/spamgate/internal/core"
)

var errRspamdResponseIdentity = errors.New("scanner returned invalid response identity")

const (
	rspamdMaxScanIDBytes = 128
	rspamdMaxMessageIDBytes = 998
)

// Scan IDs are internal correlation tokens, not display strings. Reject
// separators and controls so they cannot masquerade as multiple identifiers.
func rspamdValidScanID(value string) bool {
	if len(value) == 0 || len(value) > rspamdMaxScanIDBytes {
		return false
	}
	for _, r := range value {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || r == '-' || r == '_') {
			return false
		}
	}
	return true
}

// Message-ID is optional; keep it opaque and reject controls/invalid UTF-8.
func rspamdValidMessageID(value string) bool {
	if len(value) > rspamdMaxMessageIDBytes || !utf8.ValidString(value) {
		return false
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) {
			return false
		}
	}
	return true
}

func rspamdValidateResponseIdentity(msg core.Message) error {
	if !rspamdValidScanID(msg.ID) || !rspamdValidMessageID(msg.MessageID) {
		return errRspamdResponseIdentity
	}
	return nil
}
