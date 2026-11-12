package core

import (
 "strings"
 "testing"
)

func TestAttachmentInvisibleFormatEvidence(t *testing.T) {
 cases := []struct {
  name string
  filename string
  invisible bool
  bidi bool
 }{
  {"zero width space", "invoice\u200b.pdf", true, false},
  {"zero width joiner", "invoice\u200d.pdf", true, false},
  {"word joiner", "invoice\u2060.pdf", true, false},
  {"soft hyphen", "invoice\u00ad.pdf", true, false},
  {"bidi override", "invoice\u202e.pdf", false, true},
  {"normal unicode", "résumé.pdf", false, false},
  {"combining mark", "re\u0301sume\u0301.pdf", false, false},
  {"plain ascii", "invoice.pdf", false, false},
 }
 for _, tc := range cases {
  t.Run(tc.name, func(t *testing.T) {
   got := attachmentNameFindings(tc.filename)
   if hasAttachmentSymbol(got, "ATTACHMENT_NAME_INVISIBLE") != tc.invisible {
    t.Errorf("invisible finding mismatch: %+v", got)
   }
   if hasAttachmentSymbol(got, "ATTACHMENT_NAME_BIDI") != tc.bidi {
    t.Errorf("bidi finding mismatch: %+v", got)
   }
   label := attachmentLabel(tc.filename)
   if tc.invisible || tc.bidi {
    if !strings.Contains(label, "_") { t.Errorf("format character not redacted: %q", label) }
   } else if label != tc.filename {
    t.Errorf("benign unicode changed: got %q want %q", label, tc.filename)
   }
  })
 }
}

func TestAttachmentInvisibleDirectoryPrefix(t *testing.T) {
 name := "reports\u200b/invoice.pdf"
 got := attachmentNameFindings(name)
 if !hasAttachmentSymbol(got, "ATTACHMENT_NAME_PATH") ||
  !hasAttachmentSymbol(got, "ATTACHMENT_NAME_INVISIBLE") {
  t.Fatalf("missing original filename evidence: %+v", got)
 }
 if hasAttachmentSymbol(got, "ATTACHMENT_RISKY_EXTENSION") {
  t.Fatalf("benign PDF extension misclassified: %+v", got)
 }
 if strings.ContainsRune(attachmentLabel(name), '\u200b') {
  t.Fatal("operational label retained invisible format character")
 }
}
