package core

import "testing"

func TestAttachmentDotConfusableEvidence(t *testing.T) {
 cases := []struct {
  name string
  filename string
  ambiguous bool
  disguised bool
  risky bool
 }{
  {"one dot leader executable", "invoice\u2024exe", true, true, false},
  {"fullwidth executable", "invoice\uff0ejs", true, true, false},
  {"ideographic executable", "invoice\u3002ps1", true, true, false},
  {"halfwidth executable", "invoice\uff61scr", true, true, false},
  {"double extension", "invoice.pdf\uff0eexe", true, true, false},
  {"benign fullwidth", "invoice\uff0epdf", true, false, false},
  {"ordinary executable", "invoice.exe", false, false, true},
  {"ordinary pdf", "invoice.pdf", false, false, false},
  {"unicode letters", "résumé.pdf", false, false, false},
 }
 for _, tc := range cases {
  t.Run(tc.name, func(t *testing.T) {
   got := attachmentNameFindings(tc.filename)
   for symbol, want := range map[string]bool{
    "ATTACHMENT_NAME_DOT_CONFUSABLE": tc.ambiguous,
    "ATTACHMENT_CONFUSABLE_EXTENSION": tc.disguised,
    "ATTACHMENT_RISKY_EXTENSION": tc.risky,
   } {
    if hasAttachmentSymbol(got, symbol) != want {
     t.Errorf("%s: expected %t; findings=%+v", symbol, want, got)
    }
   }
  })
 }
}

func TestMIMEConfusableExtensionEvidence(t *testing.T) {
 raw := "From: sender@example.test\r\nTo: receiver@example.test\r\n" +
  "MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=gate\r\n\r\n" +
  "--gate\r\nContent-Type: application/octet-stream\r\n" +
  "Content-Disposition: attachment; filename*=utf-8''invoice%EF%BC%8Eexe\r\n" +
  "Content-Transfer-Encoding: binary\r\n\r\nMZpayload\r\n--gate--\r\n"
 got, err := InspectMIMEAttachments([]byte(raw))
 if err != nil { t.Fatal(err) }
 for _, symbol := range []string{"ATTACHMENT_NAME_DOT_CONFUSABLE", "ATTACHMENT_CONFUSABLE_EXTENSION", "ATTACHMENT_EXECUTABLE_CONTENT"} {
  if !hasAttachmentSymbol(got, symbol) { t.Errorf("missing %s: %+v", symbol, got) }
 }
}
