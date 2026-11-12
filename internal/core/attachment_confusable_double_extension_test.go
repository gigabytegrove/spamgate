package core

import "testing"

// A decoy extension and the dangerous suffix may be separated by different
// Unicode dot lookalikes. Both must contribute evidence, not just the suffix.
func TestConfusableDoubleExtensionDecoys(t *testing.T) {
 cases := []struct {
  name string
  filename string
  dot, dangerous, double bool
 }{
  {"fullwidth separator", "invoice.pdf\uff0eexe", true, true, true},
  {"mixed separators", "invoice\u2024pdf\uff0ejs", true, true, true},
  {"ideographic separator", "report\u3002docm", true, true, false},
  {"ordinary double extension", "report.pdf.exe", false, false, true},
  {"benign confusable", "report.pdf\uff0etxt", true, false, false},
  {"no document decoy", "report.backup\uff0eexe", true, true, false},
  {"plain document", "report.pdf", false, false, false},
 }
 for _, tc := range cases {
  t.Run(tc.name, func(t *testing.T) {
   findings := attachmentNameFindings(tc.filename)
   for _, check := range []struct{ symbol string; want bool }{
    {"ATTACHMENT_NAME_DOT_CONFUSABLE", tc.dot},
    {"ATTACHMENT_CONFUSABLE_EXTENSION", tc.dangerous},
    {"ATTACHMENT_DOUBLE_EXTENSION", tc.double},
   } {
    if got := hasAttachmentSymbol(findings, check.symbol); got != check.want {
     t.Errorf("%s: got %v, want %v; findings=%+v", check.symbol, got, check.want, findings)
    }
   }
  })
 }
}
