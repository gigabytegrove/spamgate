package transport

import (
 "context"
 "encoding/binary"
 "net"
 "strings"
 "testing"
 "time"

 "github.com/gigabytegrove/spamgate/internal/core"
)

// A callback tempfail is not a substitute for invalidating the entire
// transaction: a broken MTA/client can still send EOM after the failure.
func TestMilterCallbackFailureNeverAcceptsTruncatedOriginal(t *testing.T) {
 cases:=[]struct{name string; fail func(*testing.T,net.Conn)}{
  {"header_injection",func(t *testing.T,c net.Conn){milterSend(t,c,'L','t',[]byte("Subject\x00legitimate\r\nX-Injected: forged\x00"))}},
  {"body_before_end_headers",func(t *testing.T,c net.Conn){milterSend(t,c,'B','t',[]byte("body before N"))}},
  {"oversized_body",func(t *testing.T,c net.Conn){
    milterSend(t,c,'L','c',[]byte("From\x00sender@example.org\x00"))
    milterSend(t,c,'N','c',nil)
    chunk:=[]byte(strings.Repeat("x",60<<10))
    for n:=0;n<=milterMaxMessage;n+=len(chunk) {
      expected:=byte('c');if n+len(chunk)>milterMaxMessage {expected='t'}
      milterSend(t,c,'B',expected,chunk)
    }
  }},
 }
 for _,tc:=range cases {t.Run(tc.name,func(t *testing.T){
  st,err:=core.Open(t.TempDir());if err!=nil{t.Fatal(err)}
  if err:=st.UpdateConfig(func(c *core.Config)error{c.SetupComplete=true;return nil});err!=nil{t.Fatal(err)}
  client,server:=net.Pipe();defer client.Close();defer server.Close()
  m:=&Milter{Store:st,Scanner:&core.Scanner{Store:st,Resolver:milterStubDNS{}}}
  done:=make(chan error,1);go func(){done<-m.handle(context.Background(),server)}()
  opts:=make([]byte,12);binary.BigEndian.PutUint32(opts[:4],6);binary.BigEndian.PutUint32(opts[4:8],milterAddHeader|milterQuarantine)
  milterSend(t,client,'O','O',opts)
  milterSend(t,client,'M','c',[]byte("<sender@example.org>\x00"))
  milterSend(t,client,'R','c',[]byte("<recipient@example.org>\x00"))
  tc.fail(t,client)
  milterSend(t,client,'E','t',nil)
  if got:=st.List(10,"");len(got)!=0 {t.Fatalf("failed callback persisted/accepted message: %+v",got)}
  // The next transaction on the same connection must still work.
  milterSend(t,client,'M','c',[]byte("<sender@example.org>\x00"))
  milterSend(t,client,'R','c',[]byte("<recipient@example.org>\x00"))
  milterSend(t,client,'L','c',[]byte("From\x00sender@example.org\x00"))
  milterSend(t,client,'N','c',nil)
  milterSend(t,client,'B','c',[]byte("valid body\r\n"))
  milterSend(t,client,'E','c',nil)
  if got:=st.List(10,"");len(got)!=1 {t.Fatalf("fresh transaction not recovered: %+v",got)}
  milterSend(t,client,'Q',0,nil)
  select {case err:=<-done:if err!=nil {t.Fatal(err)};case <-time.After(2*time.Second):t.Fatal("milter did not exit")}
 })}
}

func TestMilterEOMRequiresRecipient(t *testing.T) {
 st,err:=core.Open(t.TempDir());if err!=nil{t.Fatal(err)}
 if err:=st.UpdateConfig(func(c *core.Config)error{c.SetupComplete=true;return nil});err!=nil{t.Fatal(err)}
 client,server:=net.Pipe();defer client.Close();defer server.Close()
 m:=&Milter{Store:st,Scanner:&core.Scanner{Store:st,Resolver:milterStubDNS{}}}
 done:=make(chan error,1);go func(){done<-m.handle(context.Background(),server)}()
 opts:=make([]byte,12);binary.BigEndian.PutUint32(opts[:4],6)
 milterSend(t,client,'O','O',opts)
 milterSend(t,client,'M','c',[]byte("<sender@example.org>\x00"))
 milterSend(t,client,'L','c',[]byte("From\x00sender@example.org\x00"))
 milterSend(t,client,'N','c',nil)
 milterSend(t,client,'E','t',nil)
 if len(st.List(10,""))!=0 {t.Fatal("recipient-less transaction was scanned")}
 milterSend(t,client,'Q',0,nil)
 select {case err:=<-done:if err!=nil {t.Fatal(err)};case <-time.After(2*time.Second):t.Fatal("milter did not exit")}
}
