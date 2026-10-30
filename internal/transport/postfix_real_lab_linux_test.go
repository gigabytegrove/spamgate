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
  c.Rules=append(c.Rules,
   core.Rule{ID:"ci-postfix-hold",Name:"Test Postfix hold",Kind:"sender_email",Value:"hold-lab@example.org",Action:"quarantine",Enabled:true},
   core.Rule{ID:"ci-postfix-tag",Name:"Test Sieve Junk placement",Kind:"sender_email",Value:"tag-lab@example.org",Action:"tag",Enabled:true},
  )
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
 // Count message files in new/cur only: Dovecot also writes UID/index
 // metadata and Junk lives in .Junk. Counting every file is not evidence
 // of actual mailbox disposition.
 listBox:=func(box string)([]string,error){
  root:=home
  if box!=""{root=filepath.Join(home,"."+box)}
  out,e:=exec.Command("sudo","-n","find",root,"-maxdepth","2","-type","f").CombinedOutput()
  if e!=nil{
   if strings.Contains(string(out),"No such file or directory"){return nil,nil}
   return nil,fmt.Errorf("maildir %s inventory: %w: %s",box,e,out)
  }
  var messages []string
  for _,path:=range strings.Split(strings.TrimSpace(string(out)),"\n"){
   if strings.HasPrefix(path,root+"/new/")||strings.HasPrefix(path,root+"/cur/"){
    messages=append(messages,path)
   }
  }
  return messages,nil
 }
 listMaildir:=func()([]string,error){return listBox("")}
 listJunk:=func()([]string,error){return listBox("Junk")}
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
 // A real Postfix MAIL FROM:<> DSN must retain its null reverse path in
 // SpamGate history and still reach the recipient's Maildir.
 beforeDSN:=len(accepted)
 if e:=smtp.SendMail("127.0.0.1:25",nil,"",[]string{recipient},msg("null-reverse-path","Legitimate delivery status report."));e!=nil{
  t.Fatalf("real Postfix rejected null-sender DSN: %v",e)
 }
 for i:=0;i<80;i++{
  accepted,e=listMaildir();if e!=nil{t.Fatal(e)}
  if len(accepted)>beforeDSN{break}
  time.Sleep(150*time.Millisecond)
 }
 if len(accepted)<=beforeDSN{t.Fatal("Postfix accepted null-sender DSN but no Maildir delivery was observed")}
 scans=store.List(20,"")
 if len(scans)<2||scans[0].Sender!=""||scans[0].MTAAction!="continue_requested"{
  t.Fatalf("null-sender Milter scan lost reverse path or disposition: %+v",scans)
 }
 if scans[0].MTAQueueID==""{
  t.Fatal("real Postfix null-sender Milter scan lacks queue ID correlation")
 }
 t.Logf("Real Postfix null-sender DSN reached Maildir with Milter queue ID %s",scans[0].MTAQueueID)
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
 // A forced tag must traverse Postfix, the actual Milter header mutation,
 // Dovecot LDA and Pigeonhole Sieve to the Junk mailbox, not merely be
 // recorded as a requested action in SpamGate history.
 beforeJunk,e:=listJunk();if e!=nil{t.Fatal(e)}
 if e:=smtp.SendMail("127.0.0.1:25",nil,"tag-lab@example.org",[]string{recipient},msg("tag-to-junk","Harmless tagged message for real Sieve Junk delivery."));e!=nil{
  t.Fatalf("real Postfix refused tagged test mail: %v",e)
 }
 var afterJunk []string
 for i:=0;i<80;i++{
  afterJunk,e=listJunk();if e!=nil{t.Fatal(e)}
  if len(afterJunk)>len(beforeJunk){break}
  time.Sleep(150*time.Millisecond)
 }
 if len(afterJunk)!=len(beforeJunk)+1{t.Fatalf("tagged mail did not appear exactly once in Dovecot Junk: before=%d after=%d",len(beforeJunk),len(afterJunk))}
 afterTagInbox,e:=listMaildir();if e!=nil{t.Fatal(e)}
 if len(afterTagInbox)!=len(accepted){t.Fatal("tagged mail incorrectly entered INBOX")}
 scans=store.List(20,"")
 if len(scans)==0||scans[0].Action!="tag"||scans[0].MTAAction!="spam_header_requested"{
  t.Fatalf("Milter did not request trusted tag headers: %+v",scans)
 }
 t.Logf("Real Postfix Milter tag reached Dovecot Junk exactly once; scan=%s",scans[0].ID)
 // An external sender must not be able to forge SpamGate's verdict headers
 // and force an otherwise accepted message into Junk.
 forged:=[]byte("From: <sender@example.org>\r\nTo: <"+recipient+">\r\nX-SpamGate-ID: attacker-forged\r\nX-SpamGate-Action: tag\r\nSubject: forged-verdict-lab\r\n\r\nOrdinary accepted mail.\r\n")
 if e:=smtp.SendMail("127.0.0.1:25",nil,"sender@example.org",[]string{recipient},forged);e!=nil{
  t.Fatalf("Postfix rejected forged-header safety fixture: %v",e)
 }
 var afterForged []string
 for i:=0;i<80;i++{
  afterForged,e=listMaildir();if e!=nil{t.Fatal(e)}
  if len(afterForged)>len(accepted){break}
  time.Sleep(150*time.Millisecond)
 }
 if len(afterForged)!=len(accepted)+1{t.Fatalf("forged-header accepted mail not delivered exactly once to INBOX: before=%d after=%d",len(accepted),len(afterForged))}
 junkAfterForged,e:=listJunk();if e!=nil{t.Fatal(e)}
 if len(junkAfterForged)!=len(afterJunk){t.Fatal("forged SpamGate verdict caused unauthorized Junk placement")}
 accepted=afterForged
 t.Log("Forged SpamGate verdict headers stripped; legitimate mail remained in INBOX")
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
