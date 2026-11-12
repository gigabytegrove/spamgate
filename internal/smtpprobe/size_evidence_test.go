package smtpprobe

import (
 "testing"
)

func TestSizeEvidence(t *testing.T) {
 cases := []struct {
  name string
  lines []string
  advertised, known bool
  limit uint64
  warning string
 }{
  {"identity never extension", []string{"SIZE 1000"}, false, false, 0, ""},
  {"absent", []string{"host", "PIPELINING"}, false, false, 0, ""},
  {"unbounded", []string{"host", "SIZE"}, true, false, 0, ""},
  {"zero is known", []string{"host", "size 0"}, true, true, 0, ""},
  {"numeric", []string{"host", "SIZE 10485760"}, true, true, 10485760, ""},
  {"uint64 max", []string{"host", "SIZE 18446744073709551615"}, true, true, ^uint64(0), ""},
  {"overflow", []string{"host", "SIZE 18446744073709551616"}, true, false, 0, "MALFORMED_SIZE_ADVERTISEMENT"},
  {"negative", []string{"host", "SIZE -1"}, true, false, 0, "MALFORMED_SIZE_ADVERTISEMENT"},
  {"plus", []string{"host", "SIZE +1"}, true, false, 0, "MALFORMED_SIZE_ADVERTISEMENT"},
  {"decimal", []string{"host", "SIZE 1.5"}, true, false, 0, "MALFORMED_SIZE_ADVERTISEMENT"},
  {"extra", []string{"host", "SIZE 10 extra"}, true, false, 0, "MALFORMED_SIZE_ADVERTISEMENT"},
  {"duplicate equal", []string{"host", "SIZE 100", "SIZE 100"}, true, false, 0, "DUPLICATE_SIZE_ADVERTISEMENT"},
  {"duplicate conflicting", []string{"host", "SIZE 100", "SIZE 200"}, true, false, 0, "DUPLICATE_SIZE_ADVERTISEMENT"},
  {"duplicate malformed", []string{"host", "SIZE 10", "SIZE nope"}, true, false, 0, "DUPLICATE_SIZE_ADVERTISEMENT"},
  {"keyword prefix", []string{"host", "SIZE=100"}, true, false, 0, "MALFORMED_SIZE_ADVERTISEMENT"},
  {"leading zero", []string{"host", "SIZE 00010"}, true, true, 10, ""},
  {"too many digits", []string{"host", "SIZE 000000000000000000001"}, true, false, 0, "MALFORMED_SIZE_ADVERTISEMENT"},
 }
 for _, tc := range cases {
  t.Run(tc.name, func(t *testing.T) {
   advertised, known, limit, warning := sizeEvidence(tc.lines)
   if advertised != tc.advertised || known != tc.known || limit != tc.limit || warning != tc.warning {
    t.Fatalf("got advertised=%t known=%t limit=%d warning=%q; want %t %t %d %q", advertised, known, limit, warning, tc.advertised, tc.known, tc.limit, tc.warning)
   }
  })
 }
}

func TestSizeEvidenceDoesNotAlterAuthenticationOrTLS(t *testing.T) {
 lines := []string{"mail.example ESMTP", "STARTTLS", "AUTH PLAIN", "SIZE broken"}
 tls, auth := capabilities(lines)
 if !tls || len(auth) != 1 || auth[0] != "PLAIN" {
  t.Fatalf("SIZE failure contaminated unrelated capability evidence: tls=%t auth=%v", tls, auth)
 }
 advertised, known, _, warning := sizeEvidence(lines)
 if !advertised || known || warning == "" { t.Fatalf("malformed SIZE trusted: %t %t %q", advertised, known, warning) }
}
