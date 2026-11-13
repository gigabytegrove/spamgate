package smtpprobe

import "testing"

// Duplicate mechanisms are ambiguous evidence, even if they differ only in case.
func TestAUTHDuplicateMechanismsFailClosed(t *testing.T) {
 cases := []struct {
  name string
  extensions []string
  trusted bool
  duplicateWarning bool
 }{
  {"distinct mechanisms", []string{"mail.example", "AUTH PLAIN LOGIN"}, true, false},
  {"duplicate identical", []string{"mail.example", "AUTH PLAIN PLAIN"}, false, true},
  {"duplicate case folded", []string{"mail.example", "AUTH PLAIN plain"}, false, true},
  {"duplicate legacy form", []string{"mail.example", "AUTH=LOGIN login"}, false, true},
  {"duplicate with additional valid", []string{"mail.example", "AUTH PLAIN LOGIN PLAIN"}, false, true},
  {"mixed duplicate lines", []string{"mail.example", "AUTH PLAIN", "AUTH LOGIN"}, false, false},
  {"no AUTH", []string{"mail.example", "SIZE 1000"}, false, false},
 }
 for _, tc := range cases {
  t.Run(tc.name, func(t *testing.T) {
   if got := trustworthyAUTH(tc.extensions); got != tc.trusted {
    t.Fatalf("trustworthyAUTH=%v want %v", got, tc.trusted)
   }
   _, mechanisms := capabilities(tc.extensions)
   if tc.trusted && len(mechanisms) == 0 { t.Fatal("lost valid AUTH evidence") }
   if !tc.trusted && len(mechanisms) != 0 { t.Fatalf("promoted ambiguous AUTH evidence: %v", mechanisms) }
   found := false
   for _, warning := range capabilityWarnings(tc.extensions) {
    if warning == "DUPLICATE_AUTH_MECHANISM" { found = true }
   }
   if found != tc.duplicateWarning { t.Fatalf("duplicate warning=%v want %v", found, tc.duplicateWarning) }
  })
 }
}
