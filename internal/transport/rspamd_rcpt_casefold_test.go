package transport

import (
 "net/http"
 "strings"
 "testing"
)

func TestRspamdRcptCasefoldCollection(t *testing.T) {
 h := http.Header{
  "Rcpt": {"first@example.test"},
  "rcpt": {"second@example.test"},
  "RCPT": {"third@example.test"},
 }
 m, err := rspamdReadRequestMetadata(h)
 if err != nil { t.Fatal(err) }
 if len(m.Recipients) != 3 { t.Fatalf("got %d recipients, want 3: %#v", len(m.Recipients), m.Recipients) }
 found := make(map[string]bool)
 for _, r := range m.Recipients { found[r] = true }
 for _, r := range []string{"first@example.test", "second@example.test", "third@example.test"} {
  if !found[r] { t.Fatalf("missing recipient %q: %#v", r, m.Recipients) }
 }
}

func TestRspamdRcptCasefoldRejectsInvalidAliases(t *testing.T) {
 for _, invalid := range []string{"not-an-address", "x\x00@example.test", string([]byte{0xff})} {
  h := http.Header{"Rcpt": {"valid@example.test"}, "rcpt": {invalid}}
  if _, err := rspamdReadRequestMetadata(h); err == nil {
   t.Fatalf("noncanonical invalid Rcpt accepted: %q", invalid)
  }
 }
}

func TestRspamdRcptCasefoldCombinedLimit(t *testing.T) {
 for _, count := range []int{100, 101} {
  h := http.Header{
   "Rcpt": make([]string, 50),
   "rcpt": make([]string, count-50),
  }
  for key, values := range h {
   for i := range values { values[i] = "user@example.test" }
   h[key] = values
  }
  m, err := rspamdReadRequestMetadata(h)
  if count == 100 {
   if err != nil || len(m.Recipients) != 100 { t.Fatalf("100 recipients: %v, %d", err, len(m.Recipients)) }
  } else if err == nil || !strings.Contains(err.Error(), "too many") {
   t.Fatalf("101 recipients must be rejected: %v", err)
  }
 }
}

func TestRspamdRcptCasefoldEmptyAliasRejected(t *testing.T) {
 h := http.Header{"Rcpt": {"valid@example.test"}, "rcpt": {""}}
 if _, err := rspamdReadRequestMetadata(h); err == nil { t.Fatal("empty noncanonical Rcpt accepted") }
}
