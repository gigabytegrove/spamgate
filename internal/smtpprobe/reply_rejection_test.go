package smtpprobe

import (
 "context"
 "errors"
 "fmt"
 "net"
 "strings"
 "testing"
 "time"
)

func TestSMTPReplyFailureClassification(t *testing.T) {
 for _, tc := range []struct{ code int; kind string }{
  {421,"SMTP_TEMPORARY_REJECTION"}, {450,"SMTP_TEMPORARY_REJECTION"},
  {550,"SMTP_PERMANENT_REJECTION"}, {554,"SMTP_PERMANENT_REJECTION"},
  {250,"SMTP_UNEXPECTED_REPLY"},
 } {
  err := fmt.Errorf("stage: %w", &SMTPReplyError{Stage:"ehlo",Code:tc.code})
  if got := classifyProbeFailure("ehlo",err); got != tc.kind { t.Fatalf("%d: got %s",tc.code,got) }
  finding := classifiedFailureFinding(tc.kind)
  if finding == nil || finding.Message == "" { t.Fatalf("missing actionable finding for %s",tc.kind) }
 }
}

func TestSMTPReplyErrorNeverContainsPeerText(t *testing.T) {
 err := &SMTPReplyError{Stage:"starttls",Code:454}
 if strings.Contains(err.Error(),"secret") { t.Fatal("unexpected peer content") }
 var typed *SMTPReplyError
 if !errors.As(fmt.Errorf("wrapped: %w",err),&typed) || typed.Code != 454 { t.Fatal("lost status code") }
}

func TestProbeTemporaryGreetingRejection(t *testing.T) {
 listener,err:=net.Listen("tcp","127.0.0.1:0")
 if err!=nil {t.Fatal(err)}
 defer listener.Close()
 done:=make(chan struct{})
 go func(){
  defer close(done)
  conn,e:=listener.Accept()
  if e!=nil{return}
  defer conn.Close()
  _,_=conn.Write([]byte("421 4.3.2 Service temporarily unavailable\r\n"))
 }()
 result,err:=Probe(context.Background(),Options{Address:listener.Addr().String(),Timeout:2*time.Second})
 <-done
 if err==nil || result.FailureStage!="greeting" || result.FailureKind!="SMTP_TEMPORARY_REJECTION" || result.BannerCode!=421 {
  t.Fatalf("result=%+v error=%v",result,err)
 }
}
