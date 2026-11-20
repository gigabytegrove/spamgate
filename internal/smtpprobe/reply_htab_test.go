package smtpprobe

import (
 "bufio"
 "strings"
 "testing"
)

func TestSMTPReplyHorizontalTabInText(t *testing.T) {
 cases := []struct {
  name string
  wire string
  wantCode int
  wantLines int
 }{
  {"single line", "220 Ready\tfor SMTP\r\n", 220, 1},
  {"multiline", "250-PIPELINING\tready\r\n250 AUTH\tPLAIN\r\n", 250, 2},
  {"enhanced reply", "454 4.7.0\tTLS temporarily unavailable\r\n", 454, 1},
 }
 for _, tc := range cases {
  t.Run(tc.name,func(t *testing.T){
   code,lines,err:=readReply(bufio.NewReader(strings.NewReader(tc.wire)))
   if err!=nil {t.Fatal(err)}
   if code!=tc.wantCode||len(lines)!=tc.wantLines {t.Fatalf("code=%d lines=%q",code,lines)}
  })
 }
}

func TestSMTPReplyRejectsControlBytes(t *testing.T) {
 cases:=[]struct{name,wire string}{
  {"tab in reply code","2\t0 Ready\r\n"},
  {"tab in separator","220\tReady\r\n"},
  {"nul in reply text","220 Ready\x00bad\r\n"},
  {"escape in reply text","220 Ready\x1bbad\r\n"},
  {"del in reply text","220 Ready\x7fbad\r\n"},
  {"bare lf","220 Ready\n"},
  {"embedded carriage return","220 Ready\rwrong\r\n"},
 }
 for _,tc:=range cases{
  t.Run(tc.name,func(t *testing.T){
   if _,_,err:=readReply(bufio.NewReader(strings.NewReader(tc.wire)));err==nil{
    t.Fatalf("accepted malformed reply %q",tc.wire)
   }
  })
 }
}

func TestSMTPEnhancedStatusWithHorizontalTab(t *testing.T){
 if got:=observedEnhancedStatus(454,[]string{"4.7.0\tTLS unavailable"});got!="4.7.0"{
  t.Fatalf("enhanced status = %q",got)
 }
 if got:=observedEnhancedStatus(454,[]string{"4.7.0\x1bTLS unavailable"});got!=""{
  t.Fatalf("unsafe enhanced status accepted: %q",got)
 }
}
