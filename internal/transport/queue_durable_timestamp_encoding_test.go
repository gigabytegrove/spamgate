package transport

import (
    "encoding/json"
    "strings"
    "testing"
)

// The durable writer uses encoding/json. Recovery must not accept alternative
// byte encodings that decode to the same timestamp or silently replace bytes.
func TestDurableTimestampRejectsJSONEncodingAliases(t *testing.T) {
    tests := []struct {
        name string
        raw string
        optional bool
        valid bool
    }{
        {"canonical UTC", `"2026-11-06T12:00:00Z"`, false, true},
        {"canonical offset", `"2026-11-06T07:00:00-05:00"`, false, true},
        {"canonical nanoseconds", `"2026-11-06T12:00:00.123456789Z"`, false, true},
        {"optional empty", `""`, true, true},
        {"optional zero", `"0001-01-01T00:00:00Z"`, true, true},
        {"escaped date digit", `"2026-11-06T12:00:0\u0030Z"`, false, false},
        {"escaped separator", `"2026-11-06\u005412:00:00Z"`, false, false},
        {"escaped slash", `"2026-11-06T12:00:00Z\/"`, false, false},
        {"escaped optional empty", `"\u0000"`, true, false},
        {"escaped optional zero", `"0001-01-01T00:00:00\u005a"`, true, false},
        {"invalid UTF8", string([]byte{'"', '2', '0', '2', '6', 0xff, '"'}), false, false},
    }
    for _, tc := range tests {
        t.Run(tc.name, func(t *testing.T) {
            _, err := parseDurableTimestamp(json.RawMessage(tc.raw), tc.optional)
            if (err == nil) != tc.valid {
                t.Fatalf("valid=%v, err=%v", tc.valid, err)
            }
        })
    }
}

func TestDurableTimestampAliasRejectedAcrossLifecycle(t *testing.T) {
    base := map[string]json.RawMessage{
        "attempts": json.RawMessage("0"),
        "created": json.RawMessage(`"2026-11-06T12:00:00Z"`),
        "updated": json.RawMessage(`"2026-11-06T12:00:00Z"`),
        "next_attempt": json.RawMessage(`"2026-11-06T12:00:00Z"`),
    }
    for _, key := range []string{"created", "updated", "next_attempt", "delivered_at"} {
        t.Run(key, func(t *testing.T) {
            fields := make(map[string]json.RawMessage, len(base)+1)
            for k, v := range base { fields[k] = v }
            fields[key] = json.RawMessage(`"2026-11-06T12:00:0\u0030Z"`)
            if err := validateDurableLifecycleFields(fields); err == nil {
                t.Fatalf("accepted escaped JSON alias for %s", key)
            }
        })
    }
}

func TestDurableTimestampAliasDiagnosticsDoNotExposePayload(t *testing.T) {
    secret := strings.Repeat("PRIVATE", 5)
    raw := json.RawMessage(`"2026-11-06T12:00:0\u0030Z"`)
    _, err := parseDurableTimestamp(raw, false)
    if err == nil || strings.Contains(err.Error(), secret) ||
        strings.Contains(err.Error(), string(raw)) {
        t.Fatalf("timestamp error must be sanitized: %v", err)
    }
}
