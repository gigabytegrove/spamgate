package transport

import (
	"bytes"
	"encoding/json"
	"errors"
	"time"
)

// parseDurableTimestamp validates persisted timestamp types without including
// private record values in diagnostics. Optional zero values are retained for
// compatibility with Go's time.Time JSON serialization.
func parseDurableTimestamp(raw json.RawMessage, allowEmpty bool) (time.Time, error) {
	value := bytes.TrimSpace(raw)
	if len(value) == 0 || value[0] != '"' {
		return time.Time{}, errors.New("invalid durable delivery timestamp type")
	}
	var stamp string
	if err := json.Unmarshal(value, &stamp); err != nil {
		return time.Time{}, errors.New("invalid durable delivery timestamp encoding")
	}
	if allowEmpty && (stamp == "" || stamp == "0001-01-01T00:00:00Z") {
		return time.Time{}, nil
	}
	// time.Parse accepts RFC3339-like extensions, including comma fractions
	// and variable-width hours. Persisted evidence must use the exact RFC3339
	// lexical grammar, not merely a representation the parser can interpret.
	if !durableTimestampSyntaxValid(stamp) {
		return time.Time{}, errors.New("invalid durable delivery timestamp syntax")
	}
	parsed, err := time.Parse(time.RFC3339Nano, stamp)
	if err != nil || parsed.IsZero() {
		return time.Time{}, errors.New("invalid durable delivery timestamp value")
	}
	return parsed, nil
}

// durableTimestampSyntaxValid checks RFC3339's fixed-width fields and optional
// 1..9 decimal fractional digits. The calendar and timezone range checks are
// delegated to time.Parse. This deliberately does not impose clock ordering.
func durableTimestampSyntaxValid(s string) bool {
	if len(s) < len("2006-01-02T15:04:05Z") {
		return false
	}
	digit := func(i int) bool { return s[i] >= '0' && s[i] <= '9' }
	for _, i := range [...]int{0, 1, 2, 3, 5, 6, 8, 9, 11, 12, 14, 15, 17, 18} {
		if !digit(i) {
			return false
		}
	}
	if s[4] != '-' || s[7] != '-' || s[10] != 'T' || s[13] != ':' || s[16] != ':' {
		return false
	}
	pos := 19
	if pos < len(s) && s[pos] == '.' {
		pos++
		start := pos
		for pos < len(s) && s[pos] >= '0' && s[pos] <= '9' {
			pos++
		}
		if pos == start || pos-start > 9 {
			return false
		}
	}
	if pos == len(s)-1 && s[pos] == 'Z' {
		return true
	}
	if len(s)-pos != 6 || (s[pos] != '+' && s[pos] != '-') {
		return false
	}
	return digit(pos+1) && digit(pos+2) && s[pos+3] == ':' &&
		digit(pos+4) && digit(pos+5)
}
