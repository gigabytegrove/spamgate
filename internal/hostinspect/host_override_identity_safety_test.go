package hostinspect

import (
 "strings"
 "testing"
)

func TestMilterOverrideInventoryRejectsUnsafeServiceIdentity(t *testing.T) {
 tests := []struct {
  name string
  input string
  want []string
  incomplete bool
 }{
  {"valid smtp", "submission/inet/smtpd_milters=inet:127.0.0.1:38472", []string{"submission/inet/smtpd_milters"}, false},
  {"valid punctuation", "submission-2/inet/milter_protocol=6", []string{"submission-2/inet/milter_protocol"}, false},
  {"escape sequence", "submission\x1b[31m/inet/smtpd_milters=accept", nil, true},
  {"control character", "submission\r/inet/smtpd_milters=accept", nil, true},
  {"unicode confusable", "submissiоn/inet/smtpd_milters=accept", nil, true},
  {"invalid transport", "submission/in et/smtpd_milters=accept", nil, true},
  {"oversized service", strings.Repeat("x",129)+"/inet/smtpd_milters=accept", nil, true},
  {"invalid and valid", "submission\x1b[31m/inet/smtpd_milters=accept\nsubmission/inet/milter_protocol=6", []string{"submission/inet/milter_protocol"}, true},
 }
 for _, tc := range tests {
  t.Run(tc.name, func(t *testing.T) {
   got, incomplete := InspectMilterServiceOverrides(tc.input)
   if incomplete != tc.incomplete { t.Fatalf("incomplete=%v, want %v", incomplete,tc.incomplete) }
   if len(got) != len(tc.want) { t.Fatalf("identities=%q, want %q",got,tc.want) }
   for i := range got { if got[i] != tc.want[i] { t.Fatalf("identities=%q, want %q",got,tc.want) } }
  })
 }
}

func TestMilterOverrideInventoryNeverPublishesControlSequences(t *testing.T) {
 input := "submission\x1b[0m/inet/smtpd_milters=secret\nsubmission/inet/smtpd_milters=inet:127.0.0.1:38472"
 got, incomplete := InspectMilterServiceOverrides(input)
 if !incomplete || len(got)!=1 || got[0]!="submission/inet/smtpd_milters" {
  t.Fatalf("unsafe diagnostic inventory: %q incomplete=%v",got,incomplete)
 }
 for _, identity := range got {
  if strings.ContainsAny(identity,"\x1b\r\n\t") || strings.Contains(identity,"secret") {
   t.Fatalf("unsafe identity published: %q",identity)
  }
 }
}
