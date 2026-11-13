package smtpprobe

import "testing"

// A malformed AUTH line must never produce a trusted mechanism set.
// The parser, warning generator and assessment evidence must agree.
func TestAUTHTrustAndWarningConsistency(t *testing.T) {
 cases := []struct {
  name string
  lines []string
  trusted bool
  warning string
 }{
  {"ordinary", []string{"mx.example", "AUTH PLAIN LOGIN"}, true, ""},
  {"legacy syntax", []string{"mx.example", "AUTH=PLAIN LOGIN"}, true, ""},
  {"duplicate same case", []string{"mx.example", "AUTH PLAIN PLAIN"}, false, "DUPLICATE_AUTH_MECHANISM"},
  {"duplicate mixed case", []string{"mx.example", "AUTH=LOGIN login"}, false, "DUPLICATE_AUTH_MECHANISM"},
  {"two advertisements", []string{"mx.example", "AUTH PLAIN", "AUTH LOGIN"}, false, "DUPLICATE_EXTENSION"},
  {"empty", []string{"mx.example", "AUTH"}, false, "EMPTY_AUTH_ADVERTISEMENT"},
  {"identity only", []string{"AUTH PLAIN"}, false, ""},
 }
 for _, tc := range cases {
  t.Run(tc.name, func(t *testing.T) {
   if got := trustworthyAUTH(tc.lines); got != tc.trusted {
    t.Fatalf("trustworthyAUTH=%v, want %v", got, tc.trusted)
   }
   _, mechanisms := capabilities(tc.lines)
   if tc.trusted && len(mechanisms) == 0 { t.Fatal("trusted AUTH mechanisms missing") }
   if !tc.trusted && len(mechanisms) != 0 { t.Fatalf("untrusted AUTH promoted: %v", mechanisms) }
   found := false
   for _, warning := range capabilityWarnings(tc.lines) {
    if warning == tc.warning && tc.warning != "" { found = true }
   }
   if tc.warning != "" && !found { t.Fatalf("missing warning %s", tc.warning) }
  })
 }
}
