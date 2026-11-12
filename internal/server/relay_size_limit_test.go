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

func TestRelaySizeLimitStrict(t *testing.T) {
 tests:=[]struct{name,ehlo string;want *uint64;malformed bool}{
  {"identity ignored","SIZE 999\nPIPELINING",nil,false},
  {"no size","mx.example\nPIPELINING",nil,false},
  {"unbounded","mx.example\nSIZE",nil,false},
  {"zero","mx.example\nSIZE 0",sizeTestUint(0),false},
  {"bounded","mx.example\nSIZE 10485760",sizeTestUint(10485760),false},
  {"duplicate","mx.example\nSIZE 100\nSIZE 100",nil,true},
  {"conflict","mx.example\nSIZE 100\nSIZE 200",nil,true},
  {"negative","mx.example\nSIZE -1",nil,true},
  {"plus sign","mx.example\nSIZE +1",nil,true},
  {"fraction","mx.example\nSIZE 1.5",nil,true},
  {"extra tokens","mx.example\nSIZE 100 other",nil,true},
  {"overflow","mx.example\nSIZE 18446744073709551616",nil,true},
  {"not decimal","mx.example\nSIZE 0xFF",nil,true},
 }
 for _,tt:=range tests {t.Run(tt.name,func(t *testing.T){
  got,bad:=relaySizeLimit(tt.ehlo)
  if bad!=tt.malformed {t.Fatalf("malformed=%v want %v",bad,tt.malformed)}
  if (got==nil)!=(tt.want==nil) {t.Fatalf("limit=%v want %v",got,tt.want)}
  if got!=nil && *got!=*tt.want {t.Fatalf("limit=%d want %d",*got,*tt.want)}
 })}
}

func sizeTestUint(v uint64)*uint64{return &v}

func TestRelaySizeDiagnosticDoesNotSubmitMail(t *testing.T) {
 ln,err:=net.Listen("tcp","127.0.0.1:0");if err!=nil{t.Fatal(err)}
 defer ln.Close()
 done:=make(chan []string,1)
 go func(){
  conn,err:=ln.Accept();if err!=nil{return};defer conn.Close()
  _=conn.SetDeadline(time.Now().Add(4*time.Second))
  fmt.Fprint(conn,"220 mx.test ESMTP\r\n")
  rd:=bufio.NewReader(conn)
  commands:=[]string{}
  for {
   line,err:=rd.ReadString('\n');if err!=nil{break}
   line=strings.TrimSpace(line)
   commands=append(commands,line)
   if strings.HasPrefix(line,"EHLO ") {fmt.Fprint(conn,"250-mx.test\r\n250-SIZE 4096\r\n250 PIPELINING\r\n")}
   if line=="QUIT" {fmt.Fprint(conn,"221 Bye\r\n");break}
  }
  done<-commands
 }()
 result:=probeRelay(context.Background(),ln.Addr().String(),"none",false)
 if !result.SMTPReady || !result.SIZEAdvertised || !result.SIZELimitKnown || result.SIZELimitBytes==nil || *result.SIZELimitBytes!=4096 || result.SIZEParameterMalformed {
  t.Fatalf("unexpected size evidence: %+v",result)
 }
 select {
 case commands:=<-done:
  for _,cmd:=range commands {
   if !strings.HasPrefix(cmd,"EHLO ") && cmd!="QUIT" {t.Fatalf("unexpected SMTP command: %q",cmd)}
  }
 case <-time.After(5*time.Second):t.Fatal("server did not finish")
 }
}
