package core

import (
 "fmt"
 "strings"
 "testing"
)

// multipart.Reader.NextPart silently decodes quoted-printable and removes its
// transfer-encoding header. The inspector must use NextRawPart so its own
// bounded decoder receives both the original bytes and encoding metadata.
func TestMIMEQuotedPrintableRawPartPreservesExecutableEvidence(t *testing.T) {
 for _, tc := range []struct { name, encoding, payload string }{
  {"quoted printable", "quoted-printable", "=4D=5Apayload"},
  {"base64", "base64", "TVpwYXlsb2Fk"},
 } {
  t.Run(tc.name, func(t *testing.T) {
   boundary := "spamgate-raw-part"
   raw := fmt.Sprintf("From: sender@example.invalid\r\nTo: recipient@example.invalid\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=%q\r\n\r\n--%s\r\nContent-Type: application/octet-stream\r\nContent-Disposition: attachment; filename=\"sample.bin\"\r\nContent-Transfer-Encoding: %s\r\n\r\n%s\r\n--%s--\r\n", boundary, boundary, tc.encoding, tc.payload, boundary)
   findings, err := InspectMIMEAttachments([]byte(raw))
   if err != nil { t.Fatal(err) }
   var executable, unreadable bool
   for _, f := range findings {
    executable = executable || f.Symbol == "ATTACHMENT_EXECUTABLE_CONTENT"
    unreadable = unreadable || f.Symbol == "MIME_UNREADABLE"
   }
   if !executable || unreadable { t.Fatalf("expected decoded executable evidence without unreadable marker, got %+v", findings) }
  })
 }
}

func TestMIMEQuotedPrintableRawPartDoesNotMisclassifyPlainText(t *testing.T) {
 boundary := "spamgate-raw-plain"
 raw := fmt.Sprintf("From: sender@example.invalid\r\nContent-Type: multipart/mixed; boundary=%q\r\n\r\n--%s\r\nContent-Type: application/octet-stream\r\nContent-Disposition: attachment; filename=\"note.txt\"\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\nhello=20world\r\n--%s--\r\n", boundary, boundary, boundary)
 findings, err := InspectMIMEAttachments([]byte(raw))
 if err != nil { t.Fatal(err) }
 for _, f := range findings {
  if strings.HasPrefix(f.Symbol, "ATTACHMENT_EXECUTABLE") || f.Symbol == "MIME_UNREADABLE" { t.Fatalf("unexpected evidence: %+v", findings) }
 }
}
