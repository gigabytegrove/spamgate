package core

import (
 "context"
 "encoding/base64"
 "fmt"
 "testing"
)

func attachmentFixture(filename, body string) []byte {
 return []byte(fmt.Sprintf("From: sender@example.invalid\r\nTo: recipient@example.invalid\r\nDate: Fri, 30 Oct 2026 10:00:00 +0000\r\nMessage-ID: <attachment-test@example.invalid>\r\nSubject: Attachment test\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=outer\r\n\r\n--outer\r\nContent-Type: application/octet-stream\r\nContent-Disposition: attachment; filename=\"%s\"\r\nContent-Transfer-Encoding: base64\r\n\r\n%s\r\n--outer--\r\n",filename,base64.StdEncoding.EncodeToString([]byte(body))))
}

func TestScannerDoesNotDoubleScoreOrdinaryRiskyFilename(t *testing.T) {
 store,err:=Open(t.TempDir());if err!=nil{t.Fatal(err)}
 if err:=store.UpdateConfig(func(c *Config)error{c.Settings.AttachmentInspection=true;return nil});err!=nil{t.Fatal(err)}
 msg,err:=(&Scanner{Store:store,Resolver:stubDNS{}}).Scan(context.Background(),Input{
  Raw:attachmentFixture("invoice.pdf.js","plain text body without executable signature"),
  Sender:"sender@example.invalid",Recipients:[]string{"recipient@example.invalid"},Connector:"test",
 })
 if err!=nil{t.Fatal(err)}
 countLegacy, countMIME:=0,0
 for _,f:=range msg.Findings {
  if f.Symbol=="RISKY_ATTACHMENT" {countLegacy++;if f.Score!=4 {t.Fatalf("unexpected risky filename score: %+v",f)}}
  if f.Symbol=="DOUBLE_EXTENSION" {if f.Score!=4 {t.Fatalf("unexpected double extension score: %+v",f)}}
  if f.Symbol=="ATTACHMENT_RISKY_EXTENSION" {countMIME++;if f.Score!=0 {t.Fatalf("ordinary MIME filename was scored twice: %+v",f)}}
 }
 if countLegacy!=1||countMIME!=1{t.Fatalf("expected one scored filename and one zero-weight MIME evidence item: %+v",msg.Findings)}
}

func TestScannerMacroEnabledDocumentHasReducedFilenamePenalty(t *testing.T) {
 store,err:=Open(t.TempDir());if err!=nil{t.Fatal(err)}
 msg,err:=(&Scanner{Store:store,Resolver:stubDNS{}}).Scan(context.Background(),Input{
  Raw:attachmentFixture("report.docm","plain document placeholder"),
  Sender:"sender@example.invalid",Recipients:[]string{"recipient@example.invalid"},Connector:"test",
 })
 if err!=nil{t.Fatal(err)}
 found:=false
 for _,f:=range msg.Findings {
  if f.Symbol=="RISKY_ATTACHMENT" {found=true;if f.Score!=2{t.Fatalf("macro filename weight: %+v",f)}}
 }
 if !found{t.Fatalf("missing macro filename signal: %+v",msg.Findings)}
}

func TestForwardedRFC822RiskScoredByInspector(t *testing.T) {
 inner:=attachmentFixture("invoice.pdf.js","script content")
 outer:=fmt.Sprintf("From: sender@example.invalid\r\nTo: recipient@example.invalid\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=top\r\n\r\n--top\r\nContent-Type: message/rfc822\r\nContent-Transfer-Encoding: base64\r\n\r\n%s\r\n--top--\r\n",base64.StdEncoding.EncodeToString(inner))
 found,err:=InspectMIMEAttachments([]byte(outer));if err!=nil{t.Fatal(err)}
 positive:=false
 for _,f:=range found {if f.Symbol=="ATTACHMENT_RISKY_EXTENSION"&&f.Score>0{positive=true}}
 if !positive{t.Fatalf("forwarded attachment risk was not scored: %+v",found)}
}
