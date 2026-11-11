package smtpprobe
import (
 "bufio"
 "context"
 "fmt"
 "net"
 "strings"
 "testing"
 "time"
)
func server(t *testing.T,reply string)(string,<-chan string){
 t.Helper();ln,err:=net.Listen("tcp","127.0.0.1:0");if err!=nil{t.Fatal(err)}
 commands:=make(chan string,2)
 go func(){defer ln.Close();defer close(commands);conn,err:=ln.Accept();if err!=nil{return};defer conn.Close()
  fmt.Fprint(conn,"220 test ESMTP\r\n");conn.SetDeadline(time.Now().Add(2*time.Second))
  line,err:=bufio.NewReader(conn).ReadString('\n');if err!=nil{return};commands<-strings.TrimSpace(line)
  fmt.Fprint(conn,reply)
  if strings.Contains(reply,"STARTTLS"){line,err=bufio.NewReader(conn).ReadString('\n');if err==nil{commands<-strings.TrimSpace(line);fmt.Fprint(conn,"454 TLS unavailable\r\n")}}
 }()
 return ln.Addr().String(),commands
}
func TestNoTLSFailsClosedWithoutMailCommands(t *testing.T){
 addr,commands:=server(t,"250-test\r\n250 AUTH PLAIN LOGIN\r\n")
 result,err:=Probe(context.Background(),Options{Address:addr,Timeout:time.Second,RequireTLS:true})
 if err==nil||!strings.Contains(err.Error(),"STARTTLS not advertised")||result.StartTLSVerified{t.Fatalf("result=%+v err=%v",result,err)}
 for command:=range commands{if !strings.HasPrefix(command,"EHLO "){t.Fatalf("unexpected command: %s",command)}}
}
func TestPlaintextInspectionOnlyWhenExplicit(t *testing.T){
 addr,_:=server(t,"250-test\r\n250 AUTH PLAIN LOGIN\r\n")
 result,err:=Probe(context.Background(),Options{Address:addr,Timeout:time.Second,RequireTLS:false})
 if err!=nil||result.EHLOCode!=250||len(result.AuthMechanisms)!=2{t.Fatalf("result=%+v err=%v",result,err)}
}
func TestSTARTTLSRefusalIsFailure(t *testing.T){
 addr,commands:=server(t,"250-test\r\n250 STARTTLS\r\n")
 result,err:=Probe(context.Background(),Options{Address:addr,Timeout:time.Second,RequireTLS:true})
 if err==nil||!strings.Contains(err.Error(),"454")||!result.StartTLSAdvertised||result.StartTLSVerified{t.Fatalf("result=%+v err=%v",result,err)}
 found:=false;for c:=range commands{if c=="STARTTLS"{found=true}};if !found{t.Fatal("STARTTLS not issued")}
}
func TestMalformedAndBoundedReplies(t *testing.T){
 for _,tc:=range []string{"250-a\r\n550 wrong\r\n","250-"+strings.Repeat("x",maxLine)+"\r\n","250-test\r\n"+strings.Repeat("250-more\r\n",maxLines)}{
  r:=bufio.NewReader(strings.NewReader(tc));if _,_,err:=readReply(r);err==nil{t.Fatalf("accepted malformed reply %q",tc[:10])}
 }
}
func TestInvalidOptions(t *testing.T){
 for _,opt:=range []Options{{Timeout:0},{Timeout:time.Minute+time.Second},{Timeout:time.Second,Address:"127.0.0.1:25",HelloName:"x\r\nMAIL FROM:<x>"}}{
  if _,err:=Probe(context.Background(),opt);err==nil{t.Fatalf("accepted %+v",opt)}
 }
}

func TestOversizedUnterminatedReply(t *testing.T) {
 // No newline: bounded parsing must fail instead of waiting for unbounded allocation.
 r:=bufio.NewReaderSize(strings.NewReader("250-"+strings.Repeat("x",8192)),128)
 if _,_,err:=readReply(r);err==nil||!strings.Contains(err.Error(),"exceeds limit"){t.Fatalf("unexpected error: %v",err)}
}
func TestCanceledAndNilContext(t *testing.T) {
 opt:=Options{Address:"127.0.0.1:25",Timeout:time.Second}
 if _,err:=Probe(nil,opt);err==nil{t.Fatal("nil context accepted")}
 ctx,cancel:=context.WithCancel(context.Background());cancel()
 if _,err:=Probe(ctx,opt);err!=context.Canceled{t.Fatalf("canceled context: %v",err)}
}
func TestCancellationInterruptsStalledSMTPBanner(t *testing.T) {
 ln,err:=net.Listen("tcp","127.0.0.1:0");if err!=nil{t.Fatal(err)};defer ln.Close()
 accepted:=make(chan struct{})
 done:=make(chan struct{})
 go func(){defer close(done);c,e:=ln.Accept();if e!=nil{return};defer c.Close();close(accepted);var b [1]byte;_,_=c.Read(b[:])}()
 ctx,cancel:=context.WithCancel(context.Background())
 result:=make(chan error,1)
 go func(){_,e:=Probe(ctx,Options{Address:ln.Addr().String(),Timeout:5*time.Second});result<-e}()
 select{case <-accepted:case <-time.After(time.Second):t.Fatal("probe did not connect")}
 cancel()
 select{case err:=<-result:if err==nil{t.Fatal("cancellation accepted")};case <-time.After(time.Second):t.Fatal("cancellation did not interrupt stalled read")}
 <-done
}

func TestStrictSMTPReplyFraming(t *testing.T) {
 for _,reply:=range []string{"220 greeting\n","250-test\r\n250 done\n","25x done\r\n","250 test\r"} {
  if _,_,err:=readReply(bufio.NewReader(strings.NewReader(reply)));err==nil {t.Errorf("accepted malformed SMTP reply %q",reply)}
 }
 code,lines,err:=readReply(bufio.NewReader(strings.NewReader("250-host\r\n250-STARTTLS\r\n250 AUTH PLAIN\r\n")))
 if err!=nil||code!=250||len(lines)!=3 {t.Fatalf("code=%d lines=%v err=%v",code,lines,err)}
}
func TestRejectNULNames(t *testing.T) {
 for _,opt:=range []Options{
  {Address:"127.0.0.1:25",HelloName:"bad\x00name",Timeout:time.Second},
  {Address:"127.0.0.1:25",ServerName:"bad\x00name",Timeout:time.Second},
 } {
  if _,err:=Probe(context.Background(),opt);err==nil {t.Fatalf("accepted invalid name: %+v",opt)}
 }
}

func TestRejectControlBytesInSMTPReplies(t *testing.T) {
 for _, reply := range []string{
  "220 hi\x00there\r\n",
  "250 hello\x1bworld\r\n",
  "250 hi\x7fthere\r\n",
  "250-hello\r\n250 bad\tcapability\r\n",
 } {
  _, _, err := readReply(bufio.NewReader(strings.NewReader(reply)))
  if err == nil || !strings.Contains(err.Error(), "control byte") {
   t.Errorf("accepted SMTP control byte in %q: %v", reply, err)
  }
 }
}
func TestRejectNonprintingHostnames(t *testing.T) {
 for _, name := range []string{"host\vname", "host\fname", "host\x1bname", "host\x7fname"} {
  for _, opt := range []Options{
   {Address:"127.0.0.1:25", HelloName:name, Timeout:time.Second},
   {Address:"127.0.0.1:25", ServerName:name, Timeout:time.Second},
  } {
   if _, err := Probe(context.Background(), opt); err == nil {
    t.Errorf("accepted hostname %q", name)
   }
  }
 }
}
