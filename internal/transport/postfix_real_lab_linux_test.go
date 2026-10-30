//go:build linux

package transport

import (
 "bufio"
 "bytes"
 "context"
 "encoding/json"
 "errors"
 "fmt"
 "net"
 "net/smtp"
 "net/textproto"
 "os"
 "os/exec"
 "path/filepath"
 "strings"
 "testing"
 "time"

 "github.com/gigabytegrove/spamgate/internal/core"
)

// This opt-in test calls a real Postfix smtpd and inspects the actual local
// mailbox. It NEVER runs in normal go test ./... and must only run in an
// isolated disposable Linux CI VM with the designated test account.
func TestRealPostfixMilterLocalDeliveryAndTempfail(t *testing.T) {
 if os.Getenv("SPAMGATE_POSTFIX_LAB")!="1" {t.Skip("requires disposable Postfix/Dovecot lab")}
 if os.Getenv("CI")!="true"{t.Fatal("refusing destructive lab exercise outside disposable CI runner")}
 const recipient="spamgatebeta@localhost"
 const home="/home/spamgatebeta/Maildir"
 dir:=t.TempDir()
 store,err:=core.Open(dir)
 if err!=nil{t.Fatal(err)}
 if err:=store.UpdateConfig(func(c *core.Config)error{
  c.SetupComplete=true
  c.Rules=append(c.Rules,core.Rule{ID:"ci-postfix-hold",Name:"Test Postfix hold",Kind:"sender_email",Value:"hold-lab@example.org",Action:"quarantine",Enabled:true})
  return nil
 });err!=nil{t.Fatal(err)}
 t.Setenv("SPAMGATE_TEST_RECIPIENTS",recipient)
 m:=&Milter{Addr:"127.0.0.1:38472",Store:store,Scanner:&core.Scanner{Store:store,Resolver:milterStubDNS{}}}
 _,trusted,_:=net.ParseCIDR("127.0.0.1/32")
 m.Trusted=[]*net.IPNet{trusted}
 ctx,cancel:=context.WithCancel(context.Background())
 defer cancel()
 done:=make(chan error,1)
 go func(){done<-m.Listen(ctx)}()
 ready:=false
 for i:=0;i<80;i++{
  conn,e:=net.DialTimeout("tcp",m.Addr,200*time.Millisecond)
  if e==nil{_ =conn.Close();ready=true;break}
  time.Sleep(50*time.Millisecond)
 }
 if !ready{t.Fatal("Milter failed to listen")}
 listMaildir:=func()([]string,error){
  out,e:=exec.Command("sudo","-n","find",home,"-type","f").CombinedOutput()
  if e!=nil {
   // An empty, not-yet-created Maildir is a valid initial state.
   if strings.Contains(string(out),"No such file or directory"){return nil,nil}
   return nil,fmt.Errorf("maildir inventory: %w: %s",e,out)
  }
  return strings.Fields(strings.TrimSpace(string(out))),nil
 }
 baseline,e:=listMaildir();if e!=nil{t.Fatal(e)}
 msg:=func(id,body string)[]byte{
  return []byte("From: <sender@example.org>\r\nTo: <"+recipient+">\r\nDate: Thu, 29 Oct 2026 15:00:00 +0000\r\nMessage-ID: <"+id+"@example.org>\r\nSubject: SpamGate real Postfix lab "+id+"\r\n\r\n"+body+"\r\n")
 }
 send:=func(id,body string)error{
  return smtp.SendMail("127.0.0.1:25",nil,"sender@example.org",[]string{recipient},msg(id,body))
 }
 if e:=send("legitimate","Hello, this is a normal business email with no synthetic test token.");e!=nil{
  t.Fatalf("real Postfix rejected legitimate test mail: %v",e)
 }
 var accepted []string
 for i:=0;i<80;i++{
  accepted,e=listMaildir();if e!=nil{t.Fatal(e)}
  if len(accepted)>len(baseline){break}
  time.Sleep(150*time.Millisecond)
 }
 if len(accepted)<=len(baseline){t.Fatal("Postfix accepted mail but no real local Maildir delivery observed")}
 scans:=store.List(20,"")
 if len(scans)<1||scans[0].Action!="accept"||scans[0].MTAAction!="continue_requested"{
  t.Fatalf("Milter did not save valid accept request: %+v",scans)
 }
 t.Logf("Postfix confirmed local Maildir receipt; accepted Milter scan %s",scans[0].ID)
 // Real Postfix Milter quarantine: the mail must enter Postfix's hold queue,
 // not be misreported as delivered or placed into Dovecot Junk.
 if e:=smtp.SendMail("127.0.0.1:25",nil,"hold-lab@example.org",[]string{recipient},msg("hold-request","Harmless forced Postfix hold scenario."));e!=nil{
  t.Fatalf("Postfix refused the intended hold request: %v",e)
 }
 type queueItem struct{QueueName string `json:"queue_name"`;QueueID string `json:"queue_id"`;Sender string `json:"sender"`}
 heldID:=""
 for i:=0;i<80;i++{
  output,e:=exec.Command("sudo","-n","postqueue","-j").CombinedOutput()
  if e!=nil{t.Fatalf("postqueue -j: %v %s",e,output)}
  sc:=bufio.NewScanner(bytes.NewReader(output))
  for sc.Scan(){
   var item queueItem
   if json.Unmarshal(sc.Bytes(),&item)==nil&&item.QueueName=="hold"&&item.Sender=="hold-lab@example.org"{
    heldID=item.QueueID
    break
   }
  }
  if heldID!=""{break}
  time.Sleep(100*time.Millisecond)
 }
 if heldID==""{t.Fatal("Postfix Milter hold was requested but no actual held queue entry was found")}
 afterHold,e:=listMaildir();if e!=nil{t.Fatal(e)}
 if len(afterHold)!=len(accepted){t.Fatal("held mail was delivered despite hold request")}
 scans=store.List(20,"")
 if len(scans)<2||scans[0].Action!="quarantine"||scans[0].MTAAction!="postfix_hold_requested"{
  t.Fatalf("hold request not recorded: %+v",scans)
 }
 for _,c:=range heldID{if !(c>='0'&&c<='9'||c>='a'&&c<='z'||c>='A'&&c<='Z'){t.Fatalf("unsafe queue ID %q",heldID)}}
 output,e:=exec.Command("sudo","-n","postsuper","-H",heldID).CombinedOutput()
 if e!=nil{t.Fatalf("test Postfix hold release: %v %s",e,output)}
 output,e=exec.Command("sudo","-n","postqueue","-f").CombinedOutput()
 if e!=nil{t.Fatalf("flush released test hold: %v %s",e,output)}
 for i:=0;i<80;i++{
  accepted,e=listMaildir();if e!=nil{t.Fatal(e)}
  if len(accepted)>len(afterHold){break}
  time.Sleep(150*time.Millisecond)
 }
 if len(accepted)<=len(afterHold){t.Fatal("Postfix hold released but no delivery to test Maildir observed")}
 t.Logf("Postfix hold and postsuper release observed for queue %s; Dovecot receipt checked separately",heldID)
 err=send("synthetic-reject",core.StandardGTUBE)
 if err==nil{t.Fatal("real Postfix accepted SGTUBE synthetic reject")}
 var smtpError *textproto.Error
 if !errors.As(err,&smtpError)||smtpError.Code<500||smtpError.Code>=600{
  t.Fatalf("expected Milter 5xx rejection by real Postfix, got %v",err)
 }
 afterReject,e:=listMaildir();if e!=nil{t.Fatal(e)}
 if len(afterReject)!=len(accepted){t.Fatal("rejected SGTUBE reached actual Maildir")}
 scans=store.List(20,"")
 if len(scans)<2||scans[0].Action!="reject"||scans[0].TestCase!="generic_spam"||scans[0].MTAAction!="smtp_reject_requested"{
  t.Fatalf("synthetic rejection not recorded by real Milter: %+v",scans)
 }
 // In the disposable test environment only, remove the journal to simulate
 // an interrupted/removed store. Existing scans must never be silently
 // accepted while the write path cannot persist a new decision.
 if err:=os.Remove(filepath.Join(dir,"events.jsonl"));err!=nil{t.Fatal(err)}
 err=send("storage-failure","Normal message during missing journal.")
 if err==nil{t.Fatal("Postfix returned success even though Milter could not persist audit history")}
 if !errors.As(err,&smtpError)||smtpError.Code<400||smtpError.Code>=500{
  t.Fatalf("expected temporary 4xx failure when audit cannot persist: %v",err)
 }
 afterFailure,e:=listMaildir();if e!=nil{t.Fatal(e)}
 if len(afterFailure)!=len(accepted){t.Fatal("tempfailed mail incorrectly entered Maildir")}
 t.Log("Actual Postfix Milter accept, 5xx synthetic rejection and 4xx persistence failure verified")
 cancel()
 select{
 case e:=<-done:
  if e!=nil{t.Fatalf("Milter shutdown: %v",e)}
 case <-time.After(3*time.Second):
  t.Fatal("Milter listener did not shut down")
 }
}
