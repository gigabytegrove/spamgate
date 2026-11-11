package core

import (
 "fmt"
 "strings"
 "testing"
)

func TestMissingContentTypeUsesRFC2045Default(t *testing.T) {
 raw := []byte("From: sender@example.invalid\r\nTo: recipient@example.invalid\r\n\r\nHello from a plain-text message")
 findings, err := InspectMIMEAttachments(raw)
 if err != nil { t.Fatal(err) }
 for _, finding := range findings {
  if finding.Symbol == "MIME_MALFORMED" {
   t.Fatalf("absent Content-Type is valid under RFC 2045: %+v", findings)
  }
 }
}

func TestMIMEFindingsTruncationIsExplicit(t *testing.T) {
 var raw strings.Builder
 raw.WriteString("From: sender@example.invalid\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=limit-boundary\r\n\r\n")
 for i := 0; i < 30; i++ {
  fmt.Fprintf(&raw, "--limit-boundary\r\nContent-Type: application/octet-stream; name=\\\"broken%d\r\nContent-Disposition: attachment; filename=\\\"bad%d\r\n\r\nMZpayload\r\n", i, i)
 }
 raw.WriteString("--limit-boundary--\r\n")
 findings, err := InspectMIMEAttachments([]byte(raw.String()))
 if err != nil { t.Fatal(err) }
 if len(findings) != 20 { t.Fatalf("expected bounded 20 findings, got %d: %+v",len(findings),findings) }
 if findings[len(findings)-1].Symbol != "MIME_FINDINGS_TRUNCATED" {
  t.Fatalf("missing truncation evidence: %+v", findings)
 }
}
