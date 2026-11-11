package core

import (
 "fmt"
 "strings"
 "testing"
)

func TestMalformedMIMEHeadersAreNotSilent(t *testing.T) {
 cases := []struct {
  name, headers, body, symbol string
 }{
  {"invalid content type", "Content-Type: application/octet-stream; name=\"unterminated\r\nContent-Disposition: attachment; filename=\"payload.bin\"\r\n", "MZpayload", "MIME_MALFORMED"},
  {"invalid disposition", "Content-Type: application/octet-stream\r\nContent-Disposition: attachment; filename=\"unterminated\r\n", "MZpayload", "MIME_MALFORMED"},
  {"encoded multipart", "Content-Type: multipart/mixed; boundary=boundary123\r\nContent-Transfer-Encoding: base64\r\n", "LS1ib3VuZGFyeTEyMy0t", "MIME_UNREADABLE"},
  {"unknown multipart codec", "Content-Type: multipart/mixed; boundary=boundary123\r\nContent-Transfer-Encoding: x-custom\r\n", "--boundary123--", "MIME_UNREADABLE"},
  {"missing multipart boundary", "Content-Type: multipart/mixed\r\n", "unparseable", "MIME_MALFORMED"},
 }
 for _, tc := range cases {
  t.Run(tc.name,func(t *testing.T) {
   raw := fmt.Sprintf("From: a@example.invalid\r\nTo: b@example.invalid\r\nMIME-Version: 1.0\r\n%s\r\n%s",tc.headers,tc.body)
   got,err:=InspectMIMEAttachments([]byte(raw))
   if err!=nil {t.Fatal(err)}
   for _,f:=range got {if f.Symbol==tc.symbol {return}}
   t.Fatalf("expected %s diagnostic, got %+v",tc.symbol,got)
  })
 }
}

func TestIdentityEncodedMultipartStillInspected(t *testing.T) {
 for _,encoding:=range []string{"", "7bit", "8bit", "binary"} {
  t.Run(encoding,func(t *testing.T) {
   raw:=fmt.Sprintf("From: a@example.invalid\r\nTo: b@example.invalid\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=abc123\r\nContent-Transfer-Encoding: %s\r\n\r\n--abc123\r\nContent-Type: application/octet-stream\r\nContent-Disposition: attachment; filename=\"sample.bin\"\r\n\r\nMZpayload\r\n--abc123--\r\n",encoding)
   findings,err:=InspectMIMEAttachments([]byte(raw))
   if err!=nil {t.Fatal(err)}
   var executable bool
   for _,f:=range findings {if f.Symbol=="ATTACHMENT_EXECUTABLE_CONTENT" {executable=true};if f.Symbol=="MIME_UNREADABLE" {t.Fatalf("unexpected unreadable: %+v",findings)}}
   if !executable {t.Fatalf("nested executable not found: %+v",findings)}
  })
 }
}

func TestMultipartEncodingFindingDoesNotEchoUntrustedHeader(t *testing.T) {
 raw:="From: a@example.invalid\r\nContent-Type: multipart/mixed; boundary=b\r\nContent-Transfer-Encoding: x-"+strings.Repeat("evil",30)+"\r\n\r\n--b--\r\n"
 findings,err:=InspectMIMEAttachments([]byte(raw))
 if err!=nil {t.Fatal(err)}
 if !strings.Contains(fmt.Sprint(findings),"MIME_UNREADABLE") {t.Fatalf("missing finding: %+v",findings)}
 if strings.Contains(fmt.Sprint(findings),"evil") {t.Fatalf("untrusted header echoed: %+v",findings)}
}
