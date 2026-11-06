package transport

import (
 "bytes"
 "encoding/json"
 "strings"
 "testing"
)

func TestDurableJSONSurrogateIntegrity(t *testing.T) {
 cases := []struct {
  name, payload string
  valid bool
 }{
  {"plain", `{"subject":"hello"}`, true},
  {"literal unicode", `{"subject":"日本語"}`, true},
  {"valid surrogate pair", `{"subject":"\uD83D\uDE80"}`, true},
  {"escaped backslash", `{"subject":"\\uD800"}`, true},
  {"lone high", `{"subject":"\uD800"}`, false},
  {"lone low", `{"subject":"\uDC00"}`, false},
  {"high followed by normal", `{"subject":"\uD800x"}`, false},
  {"high followed by high", `{"subject":"\uD800\uD800"}`, false},
  {"low after normal", `{"subject":"x\uDC00"}`, false},
  {"truncated escape", `{"subject":"\uD8"}`, false},
  {"malformed hex", `{"subject":"\uZZZZ"}`, false},
  {"nested malformed", `{"scan":{"subject":"\uD800"}}`, false},
  {"array malformed", `{"scan":["ok","\uDC00"]}`, false},
 }
 for _, tc := range cases {
  t.Run(tc.name, func(t *testing.T) {
   err := validateDurableJSONSurrogates([]byte(tc.payload))
   if (err == nil) != tc.valid { t.Fatalf("valid=%v err=%v", tc.valid, err) }
  })
 }
}

func TestDurableSpoolRejectsLossySurrogateRecovery(t *testing.T) {
 record := map[string]any{
  "id": strings.Repeat("a", 32), "sender": "sender@example.invalid",
  "recipients": []string{"recipient@example.invalid"},
  "subject": "safe", "created": "2026-11-06T00:00:00Z",
  "updated": "2026-11-06T00:00:00Z",
  "next_attempt": "2026-11-06T00:00:00Z",
  "attempts": 0, "state": "queued", "size": 1, "raw": "YQ==",
 }
 baseline, err := json.Marshal(record)
 if err != nil { t.Fatal(err) }
 if err := validateCanonicalSpoolRecordJSON(baseline); err != nil { t.Fatal(err) }
 for _, bad := range []string{`\uD800`, `\uDC00`, `\uD800\u0041`} {
  mutated := bytes.Replace(baseline, []byte("safe"), []byte(bad), 1)
  if err := validateCanonicalSpoolRecordJSON(mutated); err == nil {
   t.Fatalf("lossy surrogate %q accepted", bad)
  }
 }
 valid := bytes.Replace(baseline, []byte("safe"), []byte(`\uD83D\uDE80`), 1)
 if err := validateCanonicalSpoolRecordJSON(valid); err != nil {
  t.Fatalf("valid surrogate pair rejected: %v", err)
 }
}
