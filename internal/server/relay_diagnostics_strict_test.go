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

// Simulate an SMTP server that accepts HELO but rejects EHLO. Diagnostics must
// not label the connection as ESMTP-ready via net/smtp's HELO fallback.
func TestRelayProbeRejectsHELOOnlyServer(t *testing.T){
 ln,err:=net.Listen("tcp","127.0.0.1:0");if err!=nil{t.Fatal(err)}
 defer ln.Close()
 commands:=make(chan []string,1)
 go func(){
  conn,err:=ln.Accept();if err!=nil{return};defer conn.Close()
  _=conn.SetDeadline(time.Now().Add(3*time.Second))
  fmt.Fprint(conn,"220 legacy.local SMTP ready\r\n")
  rd:=bufio.NewReader(conn);var seen []string
  for{
   line,err:=rd.ReadString('\n');if err!=nil{break}
   line=strings.TrimSpace(line);seen=append(seen,line)
   if strings.HasPrefix(line,"EHLO"){fmt.Fprint(conn,"500 EHLO not supported\r\n")}
   if strings.HasPrefix(line,"HELO"){fmt.Fprint(conn,"250 legacy.local\r\n")}
  }
  commands<-seen
 }()
 got:=probeRelay(context.Background(),ln.Addr().String(),"none",false)
 if !got.TCPReachable||got.SMTPReady||!strings.Contains(got.Detail,"EHLO failed"){t.Fatalf("HELO fallback accepted: %+v",got)}
 select{
 case seen:=<-commands:
  if len(seen)!=1||!strings.HasPrefix(seen[0],"EHLO "){t.Fatalf("unexpected commands: %v",seen)}
 case <-time.After(3*time.Second):t.Fatal("server did not finish")
 }
}

func TestRelayProbeAUTHAdvertisedButNeverUsed(t *testing.T){
 ln,err:=net.Listen("tcp","127.0.0.1:0");if err!=nil{t.Fatal(err)}
 defer ln.Close()
 commands:=make(chan []string,1)
 go func(){
  conn,err:=ln.Accept();if err!=nil{return};defer conn.Close()
  _=conn.SetDeadline(time.Now().Add(3*time.Second))
  fmt.Fprint(conn,"220 mail.local ESMTP ready\r\n")
  rd:=bufio.NewReader(conn);var seen []string
  for{
   line,err:=rd.ReadString('\n');if err!=nil{break}
   line=strings.TrimSpace(line);seen=append(seen,line)
   switch{
   case strings.HasPrefix(line,"EHLO"):fmt.Fprint(conn,"250-mail.local\r\n250-SIZE 1000000\r\n250 AUTH PLAIN LOGIN\r\n")
   case line=="QUIT":fmt.Fprint(conn,"221 Bye\r\n")
   default:fmt.Fprint(conn,"500 Unsupported\r\n")
   }
   if line=="QUIT"{break}
  }
  commands<-seen
 }()
 got:=probeRelay(context.Background(),ln.Addr().String(),"none",true)
 if !got.SMTPReady||!got.AUTHAdvertised||got.TLSVerified||!strings.Contains(got.Detail,"plaintext"){t.Fatalf("incorrect diagnostic: %+v",got)}
 select{
 case seen:=<-commands:
  for _,line:=range seen{if strings.HasPrefix(line,"AUTH")||strings.HasPrefix(line,"MAIL")||strings.HasPrefix(line,"RCPT")||strings.HasPrefix(line,"DATA"){t.Fatalf("probe sent credentials or mail: %v",seen)}}
 case <-time.After(3*time.Second):t.Fatal("server did not finish")
 }
}

func TestRelayProbeSTARTTLSHandshakeFailureNotReady(t *testing.T){
 ln,err:=net.Listen("tcp","127.0.0.1:0");if err!=nil{t.Fatal(err)}
 defer ln.Close()
 go func(){
  conn,err:=ln.Accept();if err!=nil{return};defer conn.Close()
  _=conn.SetDeadline(time.Now().Add(3*time.Second))
  fmt.Fprint(conn,"220 mail.local ESMTP ready\r\n")
  rd:=bufio.NewReader(conn)
  for{
   line,err:=rd.ReadString('\n');if err!=nil{return}
   if strings.HasPrefix(line,"EHLO"){fmt.Fprint(conn,"250-mail.local\r\n250 STARTTLS\r\n")}
   if strings.HasPrefix(line,"STARTTLS"){fmt.Fprint(conn,"220 Begin TLS\r\n");return}
  }
 }()
 got:=probeRelay(context.Background(),ln.Addr().String(),"required",false)
 if !got.TCPReachable||!got.STARTTLSAdvertised||got.SMTPReady||got.TLSVerified||!strings.Contains(got.Detail,"handshake"){t.Fatalf("TLS failure classified as ready: %+v",got)}
}
