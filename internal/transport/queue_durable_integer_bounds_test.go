package transport

import (
 "encoding/json"
 "strings"
 "testing"
)

func TestDurableIntegerTokenLengthBound(t *testing.T) {
 cases := []struct {
  name string
  raw string
  valid bool
 }{
  {"maximum signed 64-bit", "9223372036854775807", true},
  {"signed overflow", "9223372036854775808", false},
  {"twenty digits", "10000000000000000000", false},
  {"long zero prefix", strings.Repeat("0", 1<<20), false},
  {"long numeric payload", strings.Repeat("9", 1<<20), false},
  {"long malformed suffix", "1"+strings.Repeat("x", 1<<20), false},
 }
 for _, tc := range cases {
  t.Run(tc.name, func(t *testing.T) {
   _, err := strictDurableNonnegativeInteger([]byte(tc.raw))
   if (err == nil) != tc.valid {
    t.Fatalf("valid=%v, err=%v", tc.valid, err)
   }
  })
 }
}

func TestDurableIntegerLengthBoundThroughLifecycle(t *testing.T) {
 base := map[string]json.RawMessage{
  "attempts": json.RawMessage("0"),
  "created": json.RawMessage(`"2026-11-06T12:00:00Z"`),
  "updated": json.RawMessage(`"2026-11-06T12:00:00Z"`),
  "next_attempt": json.RawMessage(`"2026-11-06T12:00:00Z"`),
 }
 if err := validateDurableLifecycleFields(base); err != nil {
  t.Fatalf("baseline rejected: %v", err)
 }
 for _, raw := range []string{strings.Repeat("9", 1<<20), strings.Repeat("0", 1<<20)} {
  fields := make(map[string]json.RawMessage, len(base))
  for key, value := range base { fields[key] = value }
  fields["attempts"] = json.RawMessage(raw)
  if err := validateDurableLifecycleFields(fields); err == nil {
   t.Fatal("oversized attempt counter accepted")
  }
 }
}
