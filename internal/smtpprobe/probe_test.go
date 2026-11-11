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
