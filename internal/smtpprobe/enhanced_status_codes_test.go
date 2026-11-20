package smtpprobe

import "testing"

func TestEnhancedStatusCodesEvidence(t *testing.T) {
 cases := []struct {
  name string
  lines []string
  want bool
  warning string
 }{
  {"valid", []string{"mx.example", "ENHANCEDSTATUSCODES"}, true, ""},
  {"lowercase", []string{"mx.example", "enhancedstatuscodes"}, true, ""},
  {"duplicate", []string{"mx.example", "ENHANCEDSTATUSCODES", "enhancedstatuscodes"}, false, "DUPLICATE_ENHANCEDSTATUSCODES_EXTENSION"},
  {"parameter", []string{"mx.example", "ENHANCEDSTATUSCODES unexpected"}, false, "MALFORMED_ENHANCEDSTATUSCODES_EXTENSION"},
  {"identity_not_extension", []string{"ENHANCEDSTATUSCODES"}, false, ""},
  {"unknown", []string{"mx.example", "ENHANCEDSTATUSCODESX"}, false, ""},
 }
 for _, tc := range cases {
  t.Run(tc.name, func(t *testing.T) {
   got := inspectExtensions(tc.lines)
   if got.EnhancedStatusCodes != tc.want { t.Fatalf("advertised=%v, want %v", got.EnhancedStatusCodes, tc.want) }
   if tc.warning != "" && !extensionWarning(got.Warnings, "ENHANCEDSTATUSCODES") { t.Fatalf("expected warning %s, got %v", tc.warning, got.Warnings) }
  })
 }
}

func TestEnhancedStatusCodesTLSChange(t *testing.T) {
 before := inspectExtensions([]string{"mx.example", "ENHANCEDSTATUSCODES"})
 after := inspectExtensions([]string{"mx.example", "PIPELINING"})
 found := false
 for _, f := range extensionEvidenceFindings(before, after, true) {
  if f.Code == "ENHANCEDSTATUSCODES_ADVERTISEMENT_CHANGED_AFTER_TLS" { found = true }
 }
 if !found { t.Fatal("missing post-TLS capability drift evidence") }
 ambiguous := inspectExtensions([]string{"mx.example", "ENHANCEDSTATUSCODES", "ENHANCEDSTATUSCODES"})
 for _, f := range extensionEvidenceFindings(ambiguous, after, true) {
  if f.Code == "ENHANCEDSTATUSCODES_ADVERTISEMENT_CHANGED_AFTER_TLS" { t.Fatal("ambiguous evidence cannot prove drift") }
 }
}
