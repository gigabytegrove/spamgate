package spooljson

import (
    "errors"
)

var errInvalidUnicodeEscape = errors.New("spool JSON contains invalid Unicode escape")

// validateUnicodeEscapes enforces RFC 8259's requirement that escaped UTF-16
// surrogate code units form valid pairs. encoding/json deliberately replaces
// lone surrogates with U+FFFD, so two different on-disk records can decode to
// the same struct and pass a digest over the decoded fields. Durable mail
// evidence must not silently undergo that lossy normalization.
//
// The regular JSON decoder still owns all other JSON syntax checks. This
// scanner only interprets escapes within strings; it never copies message
// contents into diagnostics and uses constant auxiliary memory.
func validateUnicodeEscapes(data []byte) error {
    inString := false
    for i := 0; i < len(data); i++ {
        switch data[i] {
        case '"':
            inString = !inString
        case '\\':
            if !inString {
                continue // The JSON parser will reject this outside a string.
            }
            if i+1 >= len(data) {
                return errInvalidUnicodeEscape
            }
            i++
            if data[i] != 'u' {
                continue // The JSON parser validates other escape forms.
            }
            first, end, ok := parseUnicodeCodeUnit(data, i+1)
            if !ok {
                return errInvalidUnicodeEscape
            }
            i = end-1
            if first >= 0xDC00 && first <= 0xDFFF {
                return errInvalidUnicodeEscape // An isolated low surrogate.
            }
            if first < 0xD800 || first > 0xDBFF {
                continue
            }
            // A high surrogate must be immediately followed by an escaped
            // low surrogate. A literal UTF-8 rune is not a substitute.
            if i+2 >= len(data) || data[i+1] != '\\' || data[i+2] != 'u' {
                return errInvalidUnicodeEscape
            }
            second, next, ok := parseUnicodeCodeUnit(data, i+3)
            if !ok || second < 0xDC00 || second > 0xDFFF {
                return errInvalidUnicodeEscape
            }
            i = next-1
        }
    }
    return nil
}

// start points to the first hexadecimal digit after a JSON \u escape.
// The returned end is the index immediately after the fourth digit.
func parseUnicodeCodeUnit(data []byte, start int) (uint16, int, bool) {
    if start > len(data) || len(data)-start < 4 {
        return 0, 0, false
    }
    var value uint16
    for _, b := range data[start : start+4] {
        value <<= 4
        switch {
        case b >= '0' && b <= '9':
            value |= uint16(b - '0')
        case b >= 'a' && b <= 'f':
            value |= uint16(b-'a') + 10
        case b >= 'A' && b <= 'F':
            value |= uint16(b-'A') + 10
        default:
            return 0, 0, false
        }
    }
    return value, start+4, true
}
