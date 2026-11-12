package core

import (
 "strings"
 "testing"
)

func TestAttachmentNamePrefixAmbiguity(t *testing.T) {
 cases := []struct {
  name string
  filename string
  want []string
  absent []string
 }{
  {"control in unix directory", "folder\x00/invoice.pdf", []string{"ATTACHMENT_NAME_PATH", "ATTACHMENT_NAME_CONTROL"}, []string{"ATTACHMENT_RISKY_EXTENSION"}},
  {"control in windows directory", "folder\r\\invoice.pdf", []string{"ATTACHMENT_NAME_PATH", "ATTACHMENT_NAME_CONTROL"}, nil},
  {"bidi in directory", "safe\u202e/invoice.pdf", []string{"ATTACHMENT_NAME_PATH", "ATTACHMENT_NAME_BIDI"}, nil},
  {"bidi in windows directory", "safe\u2066\\invoice.pdf", []string{"ATTACHMENT_NAME_PATH", "ATTACHMENT_NAME_BIDI"}, nil},
  {"ordinary directory", "reports/invoice.pdf", []string{"ATTACHMENT_NAME_PATH"}, []string{"ATTACHMENT_NAME_CONTROL", "ATTACHMENT_NAME_BIDI"}},
  {"plain filename", "invoice.pdf", nil, []string{"ATTACHMENT_NAME_PATH", "ATTACHMENT_NAME_CONTROL", "ATTACHMENT_NAME_BIDI"}},
 }
 for _, tc := range cases {
  t.Run(tc.name, func(t *testing.T) {
   findings := attachmentNameFindings(tc.filename)
   for _, symbol := range tc.want {
    if !hasAttachmentSymbol(findings, symbol) { t.Errorf("missing %s: %+v", symbol, findings) }
   }
   for _, symbol := range tc.absent {
    if hasAttachmentSymbol(findings, symbol) { t.Errorf("unexpected %s: %+v", symbol, findings) }
   }
  })
 }
}

func TestAttachmentNamePrefixEvidenceDoesNotLeakControls(t *testing.T) {
 name := "folder\r\n\u202e/invoice.pdf"
 label := attachmentLabel(name)
 if strings.ContainsAny(label, "\r\n") || strings.ContainsRune(label, '\u202e') {
  t.Fatalf("unsafe label: %q", label)
 }
 if !hasAttachmentSymbol(attachmentNameFindings(name), "ATTACHMENT_NAME_CONTROL") ||
  !hasAttachmentSymbol(attachmentNameFindings(name), "ATTACHMENT_NAME_BIDI") {
  t.Fatal("missing control and bidi evidence")
 }
}
