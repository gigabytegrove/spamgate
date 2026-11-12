package core

import (
 "testing"
)

func hasAttachmentSymbol(findings []AttachmentFinding, symbol string) bool {
 for _, f := range findings { if f.Symbol == symbol { return true } }
 return false
}

func TestAttachmentNamePathAndControlEvidence(t *testing.T) {
 cases := []struct {
  name string
  filename string
  expected []string
 }{
  {"unix path", "../payroll.pdf.exe", []string{"ATTACHMENT_NAME_PATH", "ATTACHMENT_RISKY_EXTENSION", "ATTACHMENT_DOUBLE_EXTENSION"}},
  {"windows path", `C:\\Users\\invoice.pdf.exe`, []string{"ATTACHMENT_NAME_PATH", "ATTACHMENT_RISKY_EXTENSION", "ATTACHMENT_DOUBLE_EXTENSION"}},
  {"nul", "invoice\x00.pdf", []string{"ATTACHMENT_NAME_CONTROL"}},
  {"line separator", "invoice\u2028.pdf", []string{"ATTACHMENT_NAME_CONTROL"}},
  {"ordinary", "invoice.pdf", nil},
 }
 for _, tc := range cases {
  t.Run(tc.name, func(t *testing.T) {
   findings := attachmentNameFindings(tc.filename)
   for _, symbol := range tc.expected {
    if !hasAttachmentSymbol(findings, symbol) { t.Errorf("missing %s: %+v", symbol, findings) }
   }
   if len(tc.expected) == 0 && len(findings) != 0 { t.Fatalf("benign filename flagged: %+v", findings) }
  })
 }
}

func TestMIMEAttachmentPathEvidenceIntegration(t *testing.T) {
 raw := "From: sender@example.test\r\nTo: receiver@example.test\r\n" +
  "MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=gate\r\n\r\n" +
  "--gate\r\nContent-Type: application/octet-stream\r\n" +
  "Content-Disposition: attachment; filename=\"../invoice.pdf.exe\"\r\n" +
  "Content-Transfer-Encoding: binary\r\n\r\nMZpayload\r\n--gate--\r\n"
 findings, err := InspectMIMEAttachments([]byte(raw))
 if err != nil { t.Fatal(err) }
 for _, symbol := range []string{"ATTACHMENT_NAME_PATH", "ATTACHMENT_EXECUTABLE_CONTENT"} {
  if !hasAttachmentSymbol(findings, symbol) { t.Errorf("missing %s: %+v", symbol, findings) }
 }
}
