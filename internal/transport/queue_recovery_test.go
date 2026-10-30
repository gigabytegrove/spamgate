package transport

import (
 "context"
 "errors"
 "os"
 "path/filepath"
 "strings"
 "testing"
 "time"

 "github.com/gigabytegrove/spamgate/internal/core"
)

// Simulate a crash between durable SMTP 250 and best-effort events.jsonl
// mirror. The outbox is authoritative and must recreate the missing history.
func TestDurablyAcceptedMailSurvivesMissingHistoryMirror(t *testing.T) {
 dir:=t.TempDir()
 store,err:=core.Open(dir);if err!=nil{t.Fatal(err)}
 raw:=[]byte("From: sender@example.org\r\nTo: mailbox@example.net\r\nDate: Wed, 29 Oct 2026 00:00:00 +0000\r\nSubject: delivery test\r\n\r\nMessage\r\n")
 msg:=core.Message{ID:core.ID(),Timestamp:time.Now().UTC(),Sender:"sender@example.org",Recipients:[]string{"mailbox@example.net"},Subject:"delivery test",Action:"tag",Score:7.5,Connector:"smtp",Findings:[]core.Finding{{Symbol:"AUTH_FAIL",Source:"test",Score:7.5}}}
 n:=0
 sender:=func(_ context.Context,m core.Message,b []byte)error {
  n++
  if m.ID!=msg.ID||m.Score!=msg.Score||m.Action!="tag"||len(m.Findings)!=1||string(b)!=string(raw){t.Fatalf("lost scan evidence: %+v",m)}
  return nil
 }
 q,err:=NewDeliveryQueue(dir,store,sender);if err!=nil{t.Fatal(err)}
 if err:=q.Enqueue(msg,raw);err!=nil{t.Fatal(err)}
 // New process, same durable on-disk queue, history mirror still absent.
 restarted,err:=core.Open(dir);if err!=nil{t.Fatal(err)}
 recovered,err:=NewDeliveryQueue(dir,restarted,sender);if err!=nil{t.Fatal(err)}
 if err:=recovered.ProcessDue(context.Background());err!=nil{t.Fatal(err)}
 if n!=1{t.Fatalf("expected one delivery, got %d",n)}
 got,ok:=restarted.Get(msg.ID)
 if !ok||got.Delivery!="relayed"||got.Action!="tag"||got.Score!=msg.Score||len(got.Findings)!=1{
  t.Fatalf("durably acknowledged mail not restored to history: %+v / %v",got,ok)
 }
 final,err:=recovered.Snapshot()
 if err!=nil||final.Total!=0{t.Fatalf("completed queue not cleaned: %+v %v",final,err)}
 // A second restart reads the exact original scan from events.jsonl.
 again,err:=core.Open(dir);if err!=nil{t.Fatal(err)}
 restored,ok:=again.Get(msg.ID);if !ok||restored.Delivery!="relayed"||restored.Action!="tag"{t.Fatalf("history not durable after restart %+v",restored)}
}

func TestLegacyOutboxBackfillsHistoryWithoutClaimingOriginalClassification(t *testing.T) {
 dir:=t.TempDir();store,err:=core.Open(dir);if err!=nil{t.Fatal(err)}
 msg:=core.Message{ID:core.ID(),Timestamp:time.Now().UTC(),Sender:"a@example.org",Recipients:[]string{"b@example.net"},Action:"tag"}
 q,err:=NewDeliveryQueue(dir,store,func(context.Context,core.Message,[]byte)error{return nil})
 if err!=nil{t.Fatal(err)}
 if err:=q.Enqueue(msg,[]byte("raw message"));err!=nil{t.Fatal(err)}
 q.mu.Lock()
 record,err:=q.get(msg.ID)
 if err!=nil{t.Fatal(err)}
 record.Scan=nil // Simulate an old alpha.16-format spooled job.
 if err:=q.put(record);err!=nil{t.Fatal(err)}
 q.mu.Unlock()
 restarted,err:=core.Open(dir);if err!=nil{t.Fatal(err)}
 recovered,err:=NewDeliveryQueue(dir,restarted,func(context.Context,core.Message,[]byte)error{return nil});if err!=nil{t.Fatal(err)}
 if err:=recovered.ProcessDue(context.Background());err!=nil{t.Fatal(err)}
 got,ok:=restarted.Get(msg.ID)
 if !ok||got.Action!="accept"||got.Delivery!="relayed"||len(got.Findings)!=1||got.Findings[0].Symbol!="QUEUE_HISTORY_RECOVERED"{
  t.Fatalf("legacy metadata recovery misrepresented: %+v",got)
 }
}

func TestQueueRefusesSymlinkSpoolRecord(t *testing.T) {
 dir:=t.TempDir();store,err:=core.Open(dir);if err!=nil{t.Fatal(err)}
 q,err:=NewDeliveryQueue(dir,store,func(context.Context,core.Message,[]byte)error{return nil});if err!=nil{t.Fatal(err)}
 victim:=filepath.Join(dir,"unchanged.json")
 if err:=os.WriteFile(victim,[]byte("{}"),0600);err!=nil{t.Fatal(err)}
 id:=core.ID()
 if err:=os.Symlink(victim,q.path(id));err!=nil{t.Fatal(err)}
 if _,err:=q.Snapshot();err==nil||!strings.Contains(err.Error(),"unsafe"){t.Fatalf("spool symlink not refused: %v",err)}
 b,err:=os.ReadFile(victim);if err!=nil||string(b)!="{}"{t.Fatal("symlink target changed")}
}

func TestQueueKeepsMailIfHistoryCannotBeRebuilt(t *testing.T) {
 dir:=t.TempDir();store,err:=core.Open(dir);if err!=nil{t.Fatal(err)}
 sends:=0
 q,err:=NewDeliveryQueue(dir,store,func(context.Context,core.Message,[]byte)error{sends++;return nil})
 if err!=nil{t.Fatal(err)}
 id:=core.ID()
 msg:=core.Message{ID:id,Timestamp:time.Now().UTC(),Sender:"a@example.org",Recipients:[]string{"b@example.net"},Action:"accept"}
 if err:=q.Enqueue(msg,[]byte("raw"));err!=nil{t.Fatal(err)}
 // Using a directory as the journal produces a deterministic write error,
 // including when tests run as root.
 if err:=os.Mkdir(filepath.Join(dir,"events.jsonl"),0700);err!=nil{t.Fatal(err)}
 if err:=q.ProcessDue(context.Background());err==nil{t.Fatal("history failure not reported")}
 if sends!=0{t.Fatal("sent untracked mail before rebuilding history")}
 result,err:=q.Snapshot()
 if err!=nil||result.Total!=1{t.Fatalf("spooled original lost: %+v %v",result,err)}
 if err:=os.Remove(filepath.Join(dir,"events.jsonl"));err!=nil{t.Fatal(err)}
 // Crash-recovery grace is two minutes; controlled test can advance time.
 q.now=func()time.Time{return time.Now().UTC().Add(3*time.Minute)}
 if err:=q.ProcessDue(context.Background());err!=nil&&!errors.Is(err,context.Canceled){t.Fatal(err)}
 if sends!=1{t.Fatalf("recovered mail was never attempted: %d",sends)}
}
