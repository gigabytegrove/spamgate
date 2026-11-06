package transport

import (
 "bytes"
 "encoding/json"
 "strings"
 "testing"
)

// JSON's permissive decoder replaces malformed UTF-8 with the replacement
// rune. Durable recovery must refuse that lossy transformation instead.
func TestDurableSpoolRefusesInvalidUTF8BeforeDecode(t *testing.T) {
 valid := map[string]any{
  "id": strings.Repeat("a", 32), "sender": "sender@example.invalid",
  "recipients": []string{"recipient@example.invalid"},
  "subject": "safe", "created": "2026-11-06T00:00:00Z",
  "updated": "2026-11-06T00:00:00Z",
  "next_attempt": "2026-11-06T00:00:00Z",
  "attempts": 0, "state": "queued", "size": 1, "raw": "YQ==",
 }
 original, err := json.Marshal(valid)
 if err != nil { t.Fatal(err) }
 if err := validateCanonicalSpoolRecordJSON(original); err != nil {
  t.Fatalf("valid baseline rejected: %v", err)
 }
 cases := []struct{name string; old, replacement []byte}{
  {"sender", []byte("sender@example.invalid"), []byte{'s', 'e', 'n', 'd', 'e', 'r', 0xff, '@', 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'i', 'n', 'v', 'a', 'l', 'i', 'd'}},
  {"subject", []byte("safe"), []byte{'s', 0xc0, 0xaf, 'e'}},
  {"recipient", []byte("recipient@example.invalid"), []byte{'r', 0xed, 0xa0, 0x80, '@', 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'i', 'n', 'v', 'a', 'l', 'i', 'd'}},
 }
 for _, tc := range cases {
  t.Run(tc.name, func(t *testing.T) {
   malformed := bytes.Replace(original, tc.old, tc.replacement, 1)
   if bytes.Equal(malformed, original) { t.Fatal("fixture replacement did not occur") }
   if err := validateCanonicalSpoolRecordJSON(malformed); err == nil {
    t.Fatal("malformed UTF-8 durable JSON accepted")
   }
  })
 }
}

func TestDurableSpoolValidInternationalizedIdentity(t *testing.T) {
 record := map[string]any{
  "id": strings.Repeat("b", 32), "sender": "δοκιμή@example.invalid",
  "recipients": []string{"récepteur@example.invalid"},
  "subject": "日本語", "created": "2026-11-06T00:00:00Z",
  "updated": "2026-11-06T00:00:00Z",
  "next_attempt": "2026-11-06T00:00:00Z",
  "attempts": 0, "state": "queued", "size": 1, "raw": "YQ==",
 }
 b, err := json.Marshal(record)
 if err != nil { t.Fatal(err) }
 if err := validateCanonicalSpoolRecordJSON(b); err != nil {
  t.Fatalf("valid SMTPUTF8 persisted envelope rejected: %v", err)
 }
}
