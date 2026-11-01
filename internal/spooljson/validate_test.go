package spooljson

import (
    "strings"
    "testing"
)

func TestValidateSpoolJSON(t *testing.T) {
    tests := []struct{ name, data, reason string }{
        {"normal", `{"id":"a","scan":{"findings":[{"symbol":"SAFE"}],"action":"accept"},"raw":"YWJj"}`, ""},
        {"legacy", `{"id":"a","raw":"YWJj"}`, ""},
        {"duplicate root", `{"state":"dead","state":"queued"}`, "duplicate"},
        {"duplicate casefold", `{"state":"dead","State":"queued"}`, "duplicate"},
        {"duplicate nested", `{"scan":{"action":"reject","action":"accept"}}`, "duplicate"},
        {"duplicate in array", `{"scan":{"findings":[{"score":999,"score":0}]}}`, "duplicate"},
        {"escaped duplicate", `{"state":"dead","st\u0061te":"queued"}`, "duplicate"},
        {"trailing JSON", `{"id":"a"}{"id":"b"}`, "trailing"},
        {"trailing garbage", `{"id":"a"}junk`, "trailing"},
        {"root array", `[{"id":"a"}]`, "root"},
        {"truncated", `{"scan":{"action":"accept"}`, "closed"},
        {"invalid UTF8", string([]byte{'{', '"', 'x', '"', ':', '"', 0xff, '"', '}'}), "UTF-8"},
        {"token exhaustion", `{"items":[` + strings.Repeat("0,", maxJSONTokens) + `0]}`, "budget"},
        {"deep nesting", `{"x":` + strings.Repeat("[", 65) + `0` + strings.Repeat("]", 65) + `}`, "depth"},
    }
    // Never include attacker-controlled key names in audit diagnostics.
    if err := Validate([]byte(`{"secret-address@example.invalid":1,"secret-address@example.invalid":2}`)); err == nil || strings.Contains(err.Error(), "secret-address") {
        t.Fatalf("duplicate-key diagnostic leaked an untrusted field name: %v", err)
    }
    for _, tc := range tests {
        t.Run(tc.name, func(t *testing.T) {
            err := Validate([]byte(tc.data))
            if tc.reason == "" {
                if err != nil { t.Fatalf("unexpected error: %v", err) }
            } else if err == nil || !strings.Contains(err.Error(), tc.reason) {
                t.Fatalf("expected %q, got %v", tc.reason, err)
            }
        })
    }
}
