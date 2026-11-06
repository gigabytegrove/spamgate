package transport

import (
 "encoding/json"
 "strings"
 "testing"
 "time"
)

func TestDurableTimestampValidation(t *testing.T) {
 for _, tc := range []struct {
  name string
  raw string
  allowEmpty bool
  valid bool
 }{
  {"UTC", `"2026-11-06T12:00:00Z"`, false, true},
  {"offset", `"2026-11-06T07:00:00-05:00"`, false, true},
  {"nanoseconds", `"2026-11-06T12:00:00.123456789Z"`, false, true},
  {"empty optional", `""`, true, true},
  {"empty required", `""`, false, false},
  {"null optional", "null", true, false},
  {"number", "123", false, false},
  {"boolean", "true", false, false},
  {"array", "[]", false, false},
  {"object", "{}", false, false},
  {"bad date", `"2026-02-30T12:00:00Z"`, false, false},
  {"no zone", `"2026-11-06T12:00:00"`, false, false},
  {"zero", `"0001-01-01T00:00:00Z"`, false, false},
  {"missing", "", false, false},
 } {
  t.Run(tc.name, func(t *testing.T) {
   got, err := parseDurableTimestamp(json.RawMessage(tc.raw), tc.allowEmpty)
   if (err == nil) != tc.valid {
    t.Fatalf("valid=%v, err=%v", tc.valid, err)
   }
   if tc.name == "empty optional" && !got.IsZero() {
    t.Fatal("optional empty timestamp must remain unset")
   }
  })
 }
}

func TestDurableSpoolTimestampTypesAndClockSkew(t *testing.T) {
 base := map[string]any{
  "id": strings.Repeat("a", 32),
  "sender": "",
  "recipients": []string{"user@example.org"},
  "raw": "YQ==",
  "state": "queued",
  "size": 1,
  "attempts": 0,
  "created": "2026-11-06T12:00:00Z",
  "updated": "2026-11-06T11:59:00Z",
  "next_attempt": "2026-11-06T11:58:00Z",
 }
 check := func(m map[string]any) error {
  b, err := json.Marshal(m)
  if err != nil { t.Fatal(err) }
  return validateCanonicalSpoolRecordJSON(b)
 }
 // Wall-clock adjustments must not prevent recovering otherwise valid mail.
 if err := check(base); err != nil { t.Fatalf("clock skew refused: %v", err) }
 for _, key := range []string{"created", "updated", "next_attempt"} {
  for _, value := range []any{nil, "", 42, "0001-01-01T00:00:00Z", "not-a-date"} {
   t.Run(key+"/"+strings.ReplaceAll(strings.TrimSpace(time.Now().Format("150405")), " ", ""), func(t *testing.T) {
    copy := make(map[string]any, len(base))
    for k, v := range base { copy[k] = v }
    copy[key] = value
    if err := check(copy); err == nil { t.Fatalf("invalid %s=%v accepted", key, value) }
   })
  }
 }
 for _, value := range []any{nil, 12, "0001-01-01T00:00:00Z", "invalid"} {
  copy := make(map[string]any, len(base)+1)
  for k, v := range base { copy[k] = v }
  copy["delivered_at"] = value
  if err := check(copy); err == nil { t.Fatalf("invalid delivered_at=%v accepted", value) }
 }
 copy := make(map[string]any, len(base)+1)
 for k, v := range base { copy[k] = v }
 copy["delivered_at"] = ""
 if err := check(copy); err != nil { t.Fatalf("legacy empty delivered_at rejected: %v", err) }
}
