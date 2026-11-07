package transport

import (
	"encoding/json"
	"math"
	"strconv"
	"strings"
	"testing"
)

func TestDurableIntegerBoundRegression(t *testing.T) {
	cases := []struct {
		name string
		raw string
		want int64
		ok bool
	}{
		{"zero", "0", 0, true},
		{"one", "1", 1, true},
		{"maximum", strconv.FormatInt(math.MaxInt64, 10), math.MaxInt64, true},
		{"overflow", "9223372036854775808", 0, false},
		{"twenty digits", "10000000000000000000", 0, false},
		{"megabyte", strings.Repeat("9", 1<<20), 0, false},
		{"leading zero", "01", 0, false},
		{"negative", "-1", 0, false},
		{"quoted", "`1`", 0, false},
		{"exponent", "1e1", 0, false},
		{"decimal", "1.0", 0, false},
		{"space", " 1", 0, false},
		{"empty", "", 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := strictDurableNonnegativeInteger([]byte(tc.raw))
			if (err == nil) != tc.ok || (tc.ok && got != tc.want) {
				t.Fatalf("got=%d err=%v, want=%d valid=%v", got, err, tc.want, tc.ok)
			}
		})
	}
}

func TestDurableOversizedAttemptsRejectedByLifecycle(t *testing.T) {
	for _, attempts := range []string{
		"10000000000000000000",
		strings.Repeat("9", 1<<20),
		"9223372036854775808",
	} {
		fields := map[string]json.RawMessage{
			"attempts": json.RawMessage(attempts),
			"created": json.RawMessage(`"2026-11-06T12:00:00Z"`),
			"updated": json.RawMessage(`"2026-11-06T12:00:00Z"`),
			"next_attempt": json.RawMessage(`"2026-11-06T12:00:00Z"`),
		}
		if err := validateDurableLifecycleFields(fields); err == nil {
			t.Fatalf("accepted oversized retry counter of %d bytes", len(attempts))
		}
	}
}
