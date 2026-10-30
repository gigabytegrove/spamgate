package transport

import (
 "bufio"
 "fmt"
 "net"
 "os"
 "path/filepath"
 "strings"
 "testing"
 "time"

 "github.com/gigabytegrove/spamgate/internal/core"
)

func TestSMTPScannerOutageIsRetryableAndResetsEnvelope(t *testing.T) {
 t.Setenv("SPAMGATE_CLAMAV_ADDRESS","tcp://127.0.0.1:1")
 st,err:=core.Open(t.TempDir());if err!=nil{t.Fatal(err)}
 if err:=st.UpdateConfig(func(c *core.Config)error{c.SetupComplete=true;return nil});err!=nil{t.Fatal(err)}
 testSMTPDATAOutcome(t,st,"From: sender@example.org\r\nDate: Fri, 30 Oct 2026 00:00:00 +0000\r\nSubject: legitimate\r\n\r\nMessage\r\n","451 ")
 if len(st.List(10,""))!=0 {t.Fatal("transient scan failure was persisted as accepted")}
}
func TestSMTPMalformedOriginalIsPermanentAndResetsEnvelope(t *testing.T) {
 t.Setenv("SPAMGATE_CLAMAV_ADDRESS","")
 st,err:=core.Open(t.TempDir());if err!=nil{t.Fatal(err)}
 if err:=st.UpdateConfig(func(c *core.Config)error{c.SetupComplete=true;return nil});err!=nil{t.Fatal(err)}
 testSMTPDATAOutcome(t,st,"this is not a header\r\n\r\nmessage\r\n","550 ")
}
func TestSMTPQuarantinePersistenceFailureResetsEnvelope(t *testing.T) {
 t.Setenv("SPAMGATE_CLAMAV_ADDRESS","")
 dir:=t.TempDir()
 st,err:=core.Open(dir);if err!=nil{t.Fatal(err)}
 if err:=st.UpdateConfig(func(c *core.Config)error{
  c.SetupComplete=true
  c.Rules=append(c.Rules,core.Rule{ID:"force",Name:"Force quarantine",Kind:"sender_email",Value:"sender@example.org",Action:"quarantine",Enabled:true})
  return nil
 });err!=nil{t.Fatal(err)}
 victim:=t.TempDir()
 if err:=os.Symlink(victim,filepath.Join(dir,"quarantine"));err!=nil{t.Skipf("symlink unavailable: %v",err)}
 testSMTPDATAOutcome(t,st,"From: sender@example.org\r\nSubject: held\r\n\r\nMessage\r\n","451 ")
 files,err:=os.ReadDir(victim);if err!=nil{t.Fatal(err)}
 if len(files)!=0 {t.Fatal("private original escaped quarantine data directory")}
}
func testSMTPDATAOutcome(t *testing.T,st *core.Store,raw,want string){
 t.Helper()
 listener,err:=net.Listen("tcp","127.0.0.1:0");if err!=nil{t.Fatal(err)}
 defer listener.Close()
 _,trusted,_:=net.ParseCIDR("127.0.0.1/32")
 srv:=&SMTP{Store:st,Scanner:&core.Scanner{Store:st,Resolver:milterStubDNS{}},CIDRs:[]*net.IPNet{trusted},Domains:[]string{"example.org"}}
 done:=make(chan struct{})
 go func(){defer close(done);c,e:=listener.Accept();if e==nil{srv.handle(c)}}()
 conn,err:=net.Dial("tcp",listener.Addr().String());if err!=nil{t.Fatal(err)}
 defer conn.Close()
 _=conn.SetDeadline(time.Now().Add(10*time.Second))
 reader:=bufio.NewReader(conn)
 read:=func(code string){t.Helper();line,e:=reader.ReadString('\n');if e!=nil{t.Fatal(e)};if !strings.HasPrefix(line,code){t.Fatalf("expected %q got %q",code,line)}}
 cmd:=func(line,code string){t.Helper();if _,e:=fmt.Fprintf(conn,"%s\r\n",line);e!=nil{t.Fatal(e)};read(code)}
 read("220 ")
 cmd("HELO sender.example.org","250 ")
 cmd("MAIL FROM:<sender@example.org>","250 ")
 cmd("RCPT TO:<user@example.org>","250 ")
 cmd("DATA","354 ")
 if _,e:=fmt.Fprint(conn,raw+".\r\n");e!=nil{t.Fatal(e)}
 read(want)
 cmd("RCPT TO:<user@example.org>","503 ")
 cmd("DATA","503 ")
 cmd("QUIT","221 ")
 <-done
}
