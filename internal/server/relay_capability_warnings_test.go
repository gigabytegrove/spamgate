package server

import (
 "bufio"
 "context"
 "fmt"
 "net"
 "reflect"
 "strings"
 "testing"
 "time"
)

func TestRelayCapabilityWarnings(t *testing.T) {
 tests := []struct{name, ehlo string; want []string}{
  {"normal", "mx.example\nSIZE 1000\nCHUNKING\nBINARYMIME\nAUTH PLAIN LOGIN\nPIPELINING", nil},
  {"identity ignored", "BINARYMIME\nPIPELINING", nil},
  {"missing dependency", "mx.example\nBINARYMIME", []string{"binarymime_without_chunking"}},
  {"duplicates", "mx.example\nDSN\nDSN\nSIZE 1\nSIZE 2", []string{"duplicate_extension_dsn","duplicate_extension_size"}},
  {"unexpected args", "mx.example\nSMTPUTF8 extra\nSTARTTLS extra", []string{"unexpected_parameters_smtputf8","unexpected_parameters_starttls"}},
  {"malformed", "mx.example\nBAD/KEY stuff\nCHUNKING", []string{"malformed_extension_keyword"}},
  {"combined sorted", "mx.example\nBINARYMIME extra\nBINARYMIME\nBAD/KEY", []string{"binarymime_without_chunking","duplicate_extension_binarymime","malformed_extension_keyword","unexpected_parameters_binarymime"}},
 }
 for _,tc:=range tests {t.Run(tc.name,func(t *testing.T){
  got:=relayCapabilityWarnings(tc.ehlo)
  if !reflect.DeepEqual(got,tc.want) {t.Fatalf("warnings=%v want=%v",got,tc.want)}
 })}
}

func TestRelayCapabilityWarningsReadOnlySocket(t *testing.T) {
 listener,err:=net.Listen("tcp","127.0.0.1:0")
 if err!=nil {t.Fatal(err)}
 defer listener.Close()
 done:=make(chan []string,1)
 go func(){
  conn,err:=listener.Accept()
  if err!=nil {done<-nil;return}
  defer conn.Close()
  _=conn.SetDeadline(time.Now().Add(4*time.Second))
  _,_=fmt.Fprint(conn,"220 mx.test ESMTP\r\n")
  reader:=bufio.NewReader(conn)
  var commands []string
  for {
   line,err:=reader.ReadString('\n')
   if err!=nil {break}
   line=strings.TrimSpace(line)
   commands=append(commands,line)
   if strings.HasPrefix(line,"EHLO ") {
    _,_=fmt.Fprint(conn,"250-mx.test\r\n250-BINARYMIME\r\n250-DSN\r\n250 DSN\r\n")
   }
   if line=="QUIT" {_,_=fmt.Fprint(conn,"221 bye\r\n");break}
  }
  done<-commands
 }()
 result:=probeRelay(context.Background(),listener.Addr().String(),"none",false)
 if !result.SMTPReady || !reflect.DeepEqual(result.CapabilityWarnings,[]string{"binarymime_without_chunking","duplicate_extension_dsn"}) {
  t.Fatalf("unexpected relay diagnostic: %+v",result)
 }
 select {
 case commands:=<-done:
  if len(commands)!=2 || !strings.HasPrefix(commands[0],"EHLO ") || commands[1]!="QUIT" {t.Fatalf("probe sent unexpected commands: %q",commands)}
 case <-time.After(5*time.Second):t.Fatal("SMTP probe did not complete")
 }
}
