package core

import (
 "encoding/base64"
 "fmt"
 "strings"
 "testing"
)

func hasAttachmentFinding(items []AttachmentFinding, symbol string) bool {
 for _, item := range items { if item.Symbol == symbol { return true } }
 return false
}
func TestAttachmentFilenameRiskEvidence(t *testing.T) {
 cases := []struct{
  name string
  want []string
  notWant []string
 }{
  {"invoice.pdf.js", []string{"ATTACHMENT_RISKY_EXTENSION", "ATTACHMENT_DOUBLE_EXTENSION"}, nil},
  {"invoice.pdf", nil, []string{"ATTACHMENT_RISKY_EXTENSION", "ATTACHMENT_DOUBLE_EXTENSION"}},
  {"report.docm", []string{"ATTACHMENT_RISKY_EXTENSION"}, []string{"ATTACHMENT_DOUBLE_EXTENSION"}},
  {"photo.jpg.exe", []string{"ATTACHMENT_RISKY_EXTENSION", "ATTACHMENT_DOUBLE_EXTENSION"}, nil},
  {"folder\\photo.jpg.exe", []string{"ATTACHMENT_RISKY_EXTENSION", "ATTACHMENT_DOUBLE_EXTENSION"}, nil},
  {"report\u202egpj.exe", []string{"ATTACHMENT_RISKY_EXTENSION", "ATTACHMENT_NAME_BIDI"}, nil},
  {"report.pdf. ", []string{"ATTACHMENT_NAME_TRAILING"}, []string{"ATTACHMENT_RISKY_EXTENSION"}},
  {"unnamed attachment", nil, []string{"ATTACHMENT_RISKY_EXTENSION"}},
 }
 for _, tc := range cases {
  t.Run(tc.name,func(t *testing.T){
   got:=attachmentNameFindings(tc.name)
   for _, sym:=range tc.want {if !hasAttachmentFinding(got,sym){t.Errorf("missing %s: %+v",sym,got)}}
   for _, sym:=range tc.notWant {if hasAttachmentFinding(got,sym){t.Errorf("unexpected %s: %+v",sym,got)}}
  })
 }
}
func TestAttachmentLabelSanitizesUntrustedControls(t *testing.T) {
 got:=attachmentLabel("invoice\r\nFAKE ALERT\u202e"+strings.Repeat("A",200))
 if strings.ContainsAny(got,"\r\n")||strings.ContainsRune(got,'\u202e')||len(got)>120 {
  t.Fatalf("unsafe label %q",got)
 }
}
func TestInspectMIMEAttachmentExtensionAndMagicIndependent(t *testing.T) {
 payload:=base64.StdEncoding.EncodeToString([]byte("plain text script body"))
 raw:=fmt.Sprintf("From: test@example.invalid\r\nTo: recipient@example.invalid\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=abc\r\n\r\n--abc\r\nContent-Type: application/octet-stream\r\nContent-Disposition: attachment; filename=\"invoice.pdf.js\"\r\nContent-Transfer-Encoding: base64\r\n\r\n%s\r\n--abc--\r\n",payload)
 findings,err:=InspectMIMEAttachments([]byte(raw))
 if err!=nil {t.Fatal(err)}
 for _,sym:=range []string{"ATTACHMENT_RISKY_EXTENSION","ATTACHMENT_DOUBLE_EXTENSION"} {
  if !hasAttachmentFinding(findings,sym){t.Fatalf("missing %s: %+v",sym,findings)}
 }
 if hasAttachmentFinding(findings,"ATTACHMENT_EXECUTABLE_CONTENT") {
  t.Fatalf("false executable magic: %+v",findings)
 }
}
func TestInspectMIMEBenignDocumentNoRiskyExtension(t *testing.T) {
 raw:="From: test@example.invalid\r\nTo: recipient@example.invalid\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=abc\r\n\r\n--abc\r\nContent-Type: application/octet-stream\r\nContent-Disposition: attachment; filename=\"invoice.pdf\"\r\n\r\nhello\r\n--abc--\r\n"
 findings,err:=InspectMIMEAttachments([]byte(raw))
 if err!=nil {t.Fatal(err)}
 for _,sym:=range []string{"ATTACHMENT_RISKY_EXTENSION","ATTACHMENT_DOUBLE_EXTENSION","ATTACHMENT_EXECUTABLE_CONTENT"} {
  if hasAttachmentFinding(findings,sym){t.Fatalf("benign document flagged as %s: %+v",sym,findings)}
 }
}
