package transport

import (
	"encoding/json"
	"testing"
	"time"
)

func TestDurableTimestampExactRFC3339Grammar(t *testing.T) {
	cases := []struct {
		name, stamp string
		valid bool
	}{
		{"utc", "2026-11-06T12:34:56Z", true},
		{"positive offset", "2026-11-06T12:34:56+05:30", true},
		{"negative offset", "2026-11-06T12:34:56-05:00", true},
		{"one fractional digit", "2026-11-06T12:34:56.1Z", true},
		{"nine fractional digits", "2026-11-06T12:34:56.123456789Z", true},
		{"nine digits with offset", "2026-11-06T12:34:56.123456789-05:00", true},
		{"ten fractional digits", "2026-11-06T12:34:56.1234567890Z", false},
		{"comma fraction", "2026-11-06T12:34:56,123Z", false},
		{"one digit hour", "2026-11-06T2:34:56Z", false},
		{"lowercase separator", "2026-11-06t12:34:56Z", false},
		{"space separator", "2026-11-06 12:34:56Z", false},
		{"lowercase zone", "2026-11-06T12:34:56z", false},
		{"missing zone", "2026-11-06T12:34:56", false},
		{"offset missing colon", "2026-11-06T12:34:56+0530", false},
		{"offset missing minutes", "2026-11-06T12:34:56+05", false},
		{"fraction without digits", "2026-11-06T12:34:56.Z", false},
		{"fraction with nonascii digits", "2026-11-06T12:34:56.１２Z", false},
		{"trailing bytes", "2026-11-06T12:34:56Zjunk", false},
		{"invalid calendar date", "2026-02-30T12:34:56Z", false},
		{"invalid hour", "2026-11-06T24:34:56Z", false},
		{"invalid offset", "2026-11-06T12:34:56+24:00", false},
		{"invalid negative offset", "2026-11-06T12:34:56-24:00", false},
		{"invalid offset minute", "2026-11-06T12:34:56+05:60", false},
		{"maximum lexical offset", "2026-11-06T12:34:56+23:59", true},
		{"zero required", "0001-01-01T00:00:00Z", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := json.Marshal(tc.stamp)
			if err != nil { t.Fatal(err) }
			got, err := parseDurableTimestamp(raw, false)
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v, err=%v", tc.valid, err)
			}
			if err == nil {
				expected, parseErr := time.Parse(time.RFC3339Nano, tc.stamp)
				if parseErr != nil || !got.Equal(expected) {
					t.Fatalf("timestamp changed: got=%v expected=%v parseErr=%v", got, expected, parseErr)
				}
			}
		})
	}
}

func TestDurableTimestampGrammarAppliesToAllLifecycleFields(t *testing.T) {
	base := map[string]json.RawMessage{
		"attempts": json.RawMessage("0"),
		"created": json.RawMessage(`"2026-11-06T12:00:00Z"`),
		"updated": json.RawMessage(`"2026-11-06T12:00:00Z"`),
		"next_attempt": json.RawMessage(`"2026-11-06T12:00:00Z"`),
	}
	for _, field := range []string{"created", "updated", "next_attempt", "delivered_at"} {
		t.Run(field, func(t *testing.T) {
			for _, bad := range []string{"2026-11-06T12:00:00,1Z", "2026-11-06T2:00:00Z", "2026-11-06T12:00:00.1234567890Z"} {
				fields := make(map[string]json.RawMessage, len(base)+1)
				for k, v := range base { fields[k] = v }
				encoded, err := json.Marshal(bad)
				if err != nil { t.Fatal(err) }
				fields[field] = encoded
				if err := validateDurableLifecycleFields(fields); err == nil {
					t.Fatalf("accepted noncanonical %s timestamp", field)
				}
			}
		})
	}
}
