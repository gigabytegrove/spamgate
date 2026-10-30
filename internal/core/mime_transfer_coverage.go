package core

// MIME text transfer decoding is deliberately strict: invalid encoded input
// must not be silently reinterpreted as readable text. Otherwise a partial
// or malformed transfer encoding can hide links and suspicious phrases while
// the scan trace incorrectly claims a complete content inspection.
import (
	"bytes"
	"errors"
	"io"
	"strings"
)

var (
	errInvalidBase64Text = errors.New("Invalid base64 MIME text transfer encoding")
	errInvalidQuotedPrintableText = errors.New("Invalid quoted-printable MIME text transfer encoding")
	errUnsupportedTextTransfer = errors.New("Unsupported MIME text transfer encoding")
)

func decodeMIMETextTransfer(body []byte, transfer string) ([]byte, error) {
	switch strings.ToLower(strings.TrimSpace(transfer)) {
	case "", "7bit", "8bit", "binary":
		return body, nil
	case "base64":
		// The caller already limits each MIME part to 5 MiB. Strip only
		// RFC 2045 linear whitespace, then reject malformed base64 instead
		// of scanning the raw encoded payload as ordinary message text.
		clean := make([]byte, 0, len(body))
		for _, b := range body {
			if b != ' ' && b != '\t' && b != '\r' && b != '\n' {
				clean = append(clean, b)
			}
		}
		out := make([]byte, len(clean))
		n, err := base64Decode(out, clean)
		if err != nil { return nil, errInvalidBase64Text }
		return out[:n], nil
	case "quoted-printable":
		// Go's quotedprintable.Reader is intentionally permissive: it leaves
		// invalid =XX sequences untouched. Validate the transfer syntax
		// first so a malformed payload cannot be reported as fully scanned.
		for i := 0; i < len(body); i++ {
			if body[i] != '=' { continue }
			if i+2 < len(body) && body[i+1] == '\r' && body[i+2] == '\n' {
				i += 2
				continue
			}
			if i+1 < len(body) && body[i+1] == '\n' {
				i++
				continue
			}
			if i+2 < len(body) && mimeHex(body[i+1]) && mimeHex(body[i+2]) {
				i += 2
				continue
			}
			return nil, errInvalidQuotedPrintableText
		}
		out, err := io.ReadAll(io.LimitReader(quotedPrintableReader(bytes.NewReader(body)), (2<<20)+1))
		if err != nil { return nil, errInvalidQuotedPrintableText }
		return out, nil
	default:
		return nil, errUnsupportedTextTransfer
	}
}

func mimeHex(b byte) bool {
	return b >= '0' && b <= '9' || b >= 'a' && b <= 'f' || b >= 'A' && b <= 'F'
}
