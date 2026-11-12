package server

import (
 "bufio"
 "context"
 "fmt"
 "net"
 "strings"
 "testing"
 "time"
)

func TestRelayExtensionsStrictKeywords(t *testing.T) {
 got:=relayExtensions("AUTH PLAIN\nSMTPUTF8\n8BITMIME\nPIPELINING\nSIZE 10485760\nAUTH=PLAIN\nBAD:KEY bogus\nX_TEST\n")
 for _,key:=range []string{"SMTPUTF8","8BITMIME","PIPELINING","SIZE"} {if !got[key] {t.Errorf("missing %s",key)}}
 for _,key:=range []string{"AUTH","AUTH=PLAIN","BAD:KEY","X_TEST"} {if got[key] {t.Errorf("unexpected %s",key)}}
}

func TestRelayEnvelopeCapabilityEvidence(t *testing.T) {
 ln,err:=net.Listen("tcp","127.0.0.1:0");if err!=nil{t.Fatal(err)}
 defer ln.Close()
 done:=make(chan []string,1)
 go func(){
  conn,err:=ln.Accept();if err!=nil{return};defer conn.Close()
  _=conn.SetDeadline(time.Now().Add(4*time.Second))
  fmt.Fprint(conn,"220 mx.test ESMTP\r\n")
  reader:=bufio.NewReader(conn)
  var commands []string
  for {
   line,err:=reader.ReadString('\n');if err!=nil{break}
   line=strings.TrimSpace(line);commands=append(commands,line)
   if strings.HasPrefix(line,"EHLO ") {
    fmt.Fprint(conn,"250-mx.test\r\n250-SMTPUTF8\r\n250-8BITMIME\r\n250-PIPELINING\r\n250-SIZE 12345\r\n250 AUTH PLAIN\r\n")
   }
   if line=="QUIT" {fmt.Fprint(conn,"221 bye\r\n");break}
  }
  done<-commands
 }()
 got:=probeRelay(context.Background(),ln.Addr().String(),"none",false)
 if !got.SMTPReady || !got.SMTPUTF8Advertised || !got.EightBitMIMEAdvertised || !got.PIPELININGAdvertised || !got.SIZEAdvertised || !got.AUTHMechanismsKnown {
  t.Fatalf("missing capability evidence: %+v",got)
 }
 select {
 case commands:=<-done:
  for _,cmd:=range commands {if !strings.HasPrefix(cmd,"EHLO ") && cmd!="QUIT" {t.Fatalf("unexpected command %q",cmd)}}
 case <-time.After(5*time.Second):t.Fatal("SMTP server did not complete")
 }
}

func TestRelayExtensionIdentityNotCapability(t *testing.T) {
 got:=relayExtensions("SMTPUTF8\nSIZE 100")
 if got["SMTPUTF8"] {t.Fatal("identity line treated as extension")}
 if !got["SIZE"] {t.Fatal("valid extension lost")}
}
