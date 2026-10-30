package transport

import (
	"errors"
	"fmt"
)

// validateRelayWireData rejects originals that net/smtp cannot transmit as
// RFC 5321 DATA with 8BITMIME. BINARYMIME/BDAT are not implemented. Reject
// before MAIL FROM rather than silently rewriting accepted original bytes.
// LF-only input remains supported for legacy intake; net/smtp canonicalizes
// LF to CRLF on the wire (documented, not byte-identical transport).
func validateRelayWireData(raw []byte) error {
	if len(raw) == 0 {
		return errors.New("original RFC 5322 message is empty")
	}
	if len(raw) > 10<<20 {
		return errors.New("original RFC 5322 message exceeds 10 MiB")
	}
	lineStart := 0
	for i, b := range raw {
		switch b {
		case 0:
			return fmt.Errorf("original contains NUL at byte %d; BINARYMIME is unsupported", i)
		case '\r':
			if i+1 >= len(raw) || raw[i+1] != '\n' {
				return fmt.Errorf("original contains bare CR at byte %d", i)
			}
		case '\n':
			end := i
			if end > lineStart && raw[end-1] == '\r' {
				end--
			}
			if err := checkRelayLineLength(raw[lineStart:end]); err != nil {
				return err
			}
			lineStart = i + 1
		}
	}
	return checkRelayLineLength(raw[lineStart:])
}

func checkRelayLineLength(line []byte) error {
	// RFC 5321 limits a DATA line to 1000 octets including CRLF. The
	// net/smtp dotWriter adds one dot to a line starting with '.'.
	limit := 998
	if len(line) > 0 && line[0] == '.' {
		limit--
	}
	if len(line) > limit {
		return fmt.Errorf("original contains overlong SMTP DATA line (%d octets; limit %d)", len(line), limit)
	}
	return nil
}
