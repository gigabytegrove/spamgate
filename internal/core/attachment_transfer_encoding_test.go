package core

import (
 "bytes"
 "fmt"
 "strings"
 "testing"
)

func TestAttachmentPayloadTransferEncodingAllowlist(t *testing.T) {
 for _, tc := range []struct{
  name, encoding, input string
  want string
  fails bool
 }{
  {"unspecified", "", "MZplain", "MZplain", false},
  {"7bit", "7bit", "plain", "plain", false},
  {"8bit", "8BIT", "plain", "plain", false},
  {"binary", "binary", "plain", "plain", false},
  {"base64", "BASE64", "TVpwYXlsb2Fk", "MZpayload", false},
  {"quoted printable", "quoted-printable", "MZ=70ayload", "MZpayload", false},
  {"unknown codec", "x-custom-encoding", "MZpayload", "", true},
  {"malformed base64", "base64", "%%%invalid", "", true},
 } {
  t.Run(tc.name, func(t *testing.T) {
   got, err := attachmentPayload([]byte(tc.input), tc.encoding)
   if (err != nil) != tc.fails {
    t.Fatalf("encoding %q: err=%v wantFailure=%v", tc.encoding, err, tc.fails)
   }
   if !tc.fails && string(got) != tc.want {
    t.Fatalf("decoded %q want %q", got, tc.want)
   }
  })
 }
}

func TestUnsupportedTransferEncodingIsNotClassifiedAsClean(t *testing.T) {
 const boundary = "spamgate-unknown-transfer"
 var raw bytes.Buffer
 fmt.Fprintf(&raw, "From: sender@example.invalid\r\nTo: recipient@example.invalid\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=%q\r\n\r\n--%s\r\nContent-Type: application/octet-stream\r\nContent-Disposition: attachment; filename=\"payload.bin\"\r\nContent-Transfer-Encoding: x-unsupported\r\n\r\nMZpayload\r\n--%s--\r\n", boundary, boundary, boundary)
 findings, err := InspectMIMEAttachments(raw.Bytes())
 if err != nil { t.Fatal(err) }
 var unreadable, executable bool
 for _, finding := range findings {
  unreadable = unreadable || finding.Symbol == "MIME_UNREADABLE"
  executable = executable || finding.Symbol == "ATTACHMENT_EXECUTABLE_CONTENT"
 }
 if !unreadable || executable {
  t.Fatalf("unsupported encoding must produce unreadable evidence, not raw-byte executable classification: %+v", findings)
 }
 if strings.Contains(fmt.Sprint(findings), "x-unsupported") {
  t.Fatal("untrusted encoding name must not leak into finding detail")
 }
}
