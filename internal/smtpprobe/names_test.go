package smtpprobe

import (
 "context"
 "strings"
 "testing"
 "time"
)

func TestEHLONameGrammar(t *testing.T) {
 for _,name:=range []string{"mail.example.org","localhost","mail.example.org.","[127.0.0.1]","[IPv6:2001:db8::1]"} {
  if err:=validateEHLOName(name);err!=nil {t.Errorf("valid %q: %v",name,err)}
 }
 for _,name:=range []string{"","a..b","-mail.example","mail-.example","mail_example","mail/example","mail@example","mail:25","[127.0.0.999]","[IPv6:garbage]","[::1]","host[evil]","a"+strings.Repeat("b",63)+".org","a\u00e9.example"} {
  if err:=validateEHLOName(name);err==nil {t.Errorf("accepted invalid EHLO %q",name)}
 }
}
func TestTLSNameGrammar(t *testing.T) {
 for _,name:=range []string{"mail.example.org","127.0.0.1","2001:db8::1"} {
  if err:=validateTLSName(name);err!=nil {t.Errorf("valid TLS name %q: %v",name,err)}
 }
 for _,name:=range []string{"mail@example.org","mail.example.org/path","host_name","[127.0.0.1]","host:25","a..b"} {
  if err:=validateTLSName(name);err==nil {t.Errorf("accepted invalid TLS name %q",name)}
 }
}
func TestInvalidNamesDoNotDial(t *testing.T) {
 for _,opt:=range []Options{
  {Address:"127.0.0.1:1",HelloName:"bad_name",Timeout:time.Second},
  {Address:"127.0.0.1:1",ServerName:"bad/name",Timeout:time.Second},
 } {
  _,err:=Probe(context.Background(),opt)
  if err==nil || !strings.Contains(err.Error(),"invalid") {t.Fatalf("expected validation failure, got %v",err)}
 }
}
