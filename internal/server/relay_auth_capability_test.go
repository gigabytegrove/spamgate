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

func TestRelayAuthMechanismsStrictParsing(t *testing.T) {
 cases:=[]struct{name,message string;want string}{
  {"identity ignored","AUTH PLAIN LOGIN\nSIZE 100", ""},
  {"deduplicated","mail.example\nAUTH PLAIN LOGIN plain", "PLAIN,LOGIN"},
  {"invalid tokens ignored","mail.example\nAUTH PLAIN LOGIN=broken PLAIN", "PLAIN"},
  {"no mechanisms","mail.example\nAUTH", ""},
  {"unrelated extensions","mail.example\nSTARTTLS\nSIZE 4096", ""},
 }
 for _,tc:=range cases {t.Run(tc.name,func(t *testing.T){
  got:=strings.Join(relayAuthMechanisms(tc.message),",")
  if got!=tc.want {t.Fatalf("got %q want %q",got,tc.want)}
 })}
}

func TestRelayDiagnosticAUTHCapabilityEvidence(t *testing.T) {
 for _,tc:=range []struct{name,auth string;want bool}{
  {"present","250 AUTH PLAIN LOGIN\r\n",true},
  {"empty","250 AUTH\r\n",false},
  {"absent","250 SIZE 1024\r\n",false},
 } {
  t.Run(tc.name,func(t *testing.T){
   ln,err:=net.Listen("tcp","127.0.0.1:0");if err!=nil{t.Fatal(err)}
   defer ln.Close()
   done:=make(chan []string,1)
   go func(){
    conn,err:=ln.Accept();if err!=nil{return};defer conn.Close()
    _=conn.SetDeadline(time.Now().Add(3*time.Second))
    fmt.Fprint(conn,"220 mail.test ESMTP\r\n")
    reader:=bufio.NewReader(conn)
    var commands []string
    for {
     line,err:=reader.ReadString('\n');if err!=nil{break}
     line=strings.TrimSpace(line);commands=append(commands,line)
     if strings.HasPrefix(line,"EHLO ") {fmt.Fprint(conn,"250-mail.test\r\n"+tc.auth)}
     if line=="QUIT" {fmt.Fprint(conn,"221 Bye\r\n");break}
    }
    done<-commands
   }()
   got:=probeRelay(context.Background(),ln.Addr().String(),"none",true)
   if !got.SMTPReady || got.AUTHMechanismsKnown!=tc.want {t.Fatalf("incorrect capability evidence: %+v",got)}
   if tc.want && strings.Join(got.AUTHMechanisms,",")!="PLAIN,LOGIN" {t.Fatalf("mechanisms: %+v",got)}
   if !strings.Contains(got.Detail,"plaintext") {t.Fatalf("missing plaintext warning: %+v",got)}
   select {
   case commands:=<-done:
    for _,command:=range commands {
     if !strings.HasPrefix(command,"EHLO ") && command!="QUIT" {t.Fatalf("probe sent forbidden command: %q",command)}
    }
   case <-time.After(4*time.Second):t.Fatal("SMTP server did not finish")
   }
  })
 }
}
