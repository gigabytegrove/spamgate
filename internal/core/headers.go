package core

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// A bounded raw header snapshot is captured at message-ingest time. The
// message body and attachments are never stored by this feature.
const MaxStoredHeaderBytes = 256 * 1024

// CaptureHeaders returns ONLY the RFC 5322 header section, including original
// folding and field order. A snapshot may be truncated if the header block
// exceeds 256 KiB; this is reported to the administrator.
func CaptureHeaders(raw []byte) (snapshot []byte, truncated bool) {
	crlf := bytes.Index(raw, []byte("\r\n\r\n"))
	lf := bytes.Index(raw, []byte("\n\n"))
	end := crlf
	if end < 0 || lf >= 0 && lf < end {
		end = lf
	}
	if end < 0 {
		return nil, false
	}
	if end > MaxStoredHeaderBytes {
		return append([]byte(nil), raw[:MaxStoredHeaderBytes]...), true
	}
	return append([]byte(nil), raw[:end]...), false
}

// SavedHeaders is a source-limited representation of what SpamGate observed.
// 'Original' means the MTA supplied this text; it is NOT a final delivered
// message (the destination MTA may add more Received or Authentication-Results).
type SavedHeaders struct {
	Raw       string `json:"raw"`
	Source    string `json:"source"`
	Truncated bool   `json:"truncated"`
	Bytes     int    `json:"bytes"`
}

func (s *Store) Headers(id string) (SavedHeaders, error) {
	if !validID(id) {
		return SavedHeaders{}, errors.New("invalid scan ID")
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if _, ok := s.messages[id]; !ok {
		return SavedHeaders{}, os.ErrNotExist
	}
	content, err := os.ReadFile(filepath.Join(s.dir, "headers", id+".hdr"))
	source := "Captured when SpamGate scanned this message"
	if errors.Is(err, os.ErrNotExist) {
		// Older quarantines may retain a full original. Never return the body.
		original, e := os.ReadFile(filepath.Join(s.dir, "quarantine", id+".eml"))
		if e != nil {
			return SavedHeaders{}, os.ErrNotExist
		}
		content, _ = CaptureHeaders(original)
		source = "Recovered from a retained quarantine original"
	} else if err != nil {
		return SavedHeaders{}, err
	}
	if len(content) == 0 {
		return SavedHeaders{}, os.ErrNotExist
	}
	if len(content) > MaxStoredHeaderBytes {
		return SavedHeaders{}, fmt.Errorf("invalid saved headers size")
	}
	truncated := len(content) == MaxStoredHeaderBytes
	if truncated {
		// The read view never invents a header boundary or displays body bytes.
		content = bytes.TrimRight(content, "\r\n")
	}
	// Replace only NUL characters to keep the JSON/text UI safe. Preserve
	// folding and whitespace exactly otherwise, including non-ASCII header text.
	raw := strings.ReplaceAll(string(content), "\x00", "�")
	return SavedHeaders{Raw: raw, Source: source, Truncated: truncated, Bytes: len(content)}, nil
}
