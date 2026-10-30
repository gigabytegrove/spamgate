package transport

import (
 "bufio"
 "context"
 "fmt"
 "net"
 "strings"
 "testing"
 "time"

 "github.com/gigabytegrove/spamgate/internal/core"
)

func TestSMTPStrictMailAndRecipientParameters(t *testing.T) {
 valid:=[]string{
  "MAIL FROM:<>",
  "MAIL FROM:<sender@example.org>",
  "MAIL FROM:<sender@example.org> SIZE=0",
  "MAIL FROM:<sender@example.org> BODY=8BITMIME SIZE=10485760",
  "MAIL FROM:<sender@example.org> BODY=7BIT",
 }
 for _,line:=range valid {
  if _,_,err:=parseSMTPMail(line);err!=nil{t.Errorf("%q: %v",line,err)}
 }
 invalid:=[]string{
  "MAIL FROM:sender@example.org",
  "MAIL FROM:<sender@example.org>garbage",
  "MAIL FROM:<sender@example.org> AUTH=secret",
  "MAIL FROM:<sender@example.org> SIZE=abc",
  "MAIL FROM:<sender@example.org> SIZE=-1",
  "MAIL FROM:<sender@example.org> SIZE=9999999999999999999999999",
  "MAIL FROM:<sender@example.org> SIZE=1 SIZE=2",
  "MAIL FROM:<sender@example.org> BODY=BINARYMIME",
  "MAIL FROM:<sender@example.org> BODY=7BIT BODY=8BITMIME",
  "MAIL FROM:<sender@example.org",
 }
 for _,line:=range invalid {
  if _,_,err:=parseSMTPMail(line);err==nil{t.Errorf("accepted malformed envelope %q",line)}
 }
 if _,err:=parseSMTPRecipient("RCPT TO:<recipient@example.org> NOTIFY=SUCCESS");err==nil{t.Fatal("silently discarded unadvertised DSN request")}
 if _,err:=parseSMTPRecipient("RCPT TO:recipient@example.org");err==nil{t.Fatal("accepted unbracketed recipient")}
 if _,err:=parseSMTPRecipient("RCPT TO:<>");err==nil{t.Fatal("accepted empty recipient")}
 if _,err:=parseSMTPRecipient("RCPT TO:<recipient@example.org>");err!=nil{t.Fatal(err)}
}

func TestSMTPFailedMAILResetsPriorTransaction(t *testing.T) {
 store,err:=core.Open(t.TempDir());if err!=nil{t.Fatal(err)}
 if err:=store.UpdateConfig(func(c *core.Config)error{c.SetupComplete=true;return nil});err!=nil{t.Fatal(err)}
 listener,err:=net.Listen("tcp","127.0.0.1:0");if err!=nil{t.Fatal(err)}
 defer listener.Close()
 _,trusted,_:=net.ParseCIDR("127.0.0.1/32")
 srv:=&SMTP{Store:store,CIDRs:[]*net.IPNet{trusted},Domains:[]string{"example.org"}}
 done:=make(chan struct{})
 go func(){defer close(done);peer,e:=listener.Accept();if e==nil{srv.handle(peer)}}()
 conn,err:=net.Dial("tcp",listener.Addr().String());if err!=nil{t.Fatal(err)}
 defer conn.Close()
 _=conn.SetDeadline(time.Now().Add(10*time.Second))
 reader:=bufio.NewReader(conn)
 read:=func(code string){t.Helper();line,e:=reader.ReadString('\n');if e!=nil{t.Fatal(e)};if !strings.HasPrefix(line,code){t.Fatalf("expected %s got %q",code,line)}}
 send:=func(line,code string){t.Helper();if _,e:=fmt.Fprintf(conn,"%s\r\n",line);e!=nil{t.Fatal(e)};read(code)}
 read("220 ")
 send("HELO client.example.org","250 ")
 send("MAIL FROM:<sender@example.org>","250 ")
 send("RCPT TO:<recipient@example.org>","250 ")
 send("MAIL FROM:<sender@example.org> SIZE=99999999","552 ")
 send("DATA","503 ")
 send("RCPT TO:<recipient@example.org>","503 ")
 send("MAIL FROM:<sender@example.org> SIZE=not-a-number","501 ")
 send("RCPT TO:<recipient@example.org>","503 ")
 send("MAIL FROM:<sender@example.org> BODY=8BITMIME SIZE=12","250 ")
 send("RCPT TO:<recipient@example.org> NOTIFY=SUCCESS","501 ")
 send("RCPT TO:<recipient@example.org>","250 ")
 send("MAIL FROM:<sender@example.org>bad","501 ")
 send("DATA","503 ")
 send("QUIT","221 ")
 <-done
}

func TestSMTPListenerRefusesMissingDurableOutbox(t *testing.T) {
 srv:=&SMTP{Addr:"127.0.0.1:0"}
 if err:=srv.Listen(context.Background());err==nil||!strings.Contains(err.Error(),"durable delivery queue"){
  t.Fatalf("unsafe listener started without spool: %v",err)
 }
}
