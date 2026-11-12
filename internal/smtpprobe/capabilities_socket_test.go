package smtpprobe

import (
 "context"
 "strings"
 "testing"
 "time"
)

// The test server advertises no extensions, despite its identity resembling
// an extension keyword. The probe must not attempt a TLS command.
func TestProbeIdentityCannotAdvertiseTLS(t *testing.T) {
 addr,commands:=server(t,"250 STARTTLS\r\n")
 result,err:=Probe(context.Background(),Options{Address:addr,Timeout:time.Second,RequireTLS:true})
 if err==nil || !strings.Contains(err.Error(),"STARTTLS not advertised") || result.StartTLSAdvertised {
  t.Fatalf("identity was treated as capability: result=%+v err=%v",result,err)
 }
 for command:=range commands {
  if !strings.HasPrefix(command,"EHLO ") {t.Fatalf("unexpected command: %q",command)}
 }
}

func TestProbeRejectsMalformedAuthenticationTokens(t *testing.T) {
 addr,commands:=server(t,"250-host\r\n250 AUTH PLAIN=invalid bad/token\r\n")
 result,err:=Probe(context.Background(),Options{Address:addr,Timeout:time.Second})
 if err!=nil || len(result.AuthMechanisms)!=0 {
  t.Fatalf("invalid authentication evidence: result=%+v err=%v",result,err)
 }
 for command:=range commands {
  if !strings.HasPrefix(command,"EHLO ") {t.Fatalf("unexpected command: %q",command)}
 }
}
