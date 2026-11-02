package transport

import (
 "bytes"
 "context"
 "errors"
 "os"
 "path/filepath"
 "strings"
 "testing"
 "time"

 "github.com/gigabytegrove/spamgate/internal/core"
)

func retryAuditFixture(t *testing.T) (*DeliveryQueue, *core.Store, string, []byte, *int) {
 t.Helper()
 sends:=new(int)
 q,store,_:=newRecoveryQueue(t,func(_ context.Context,_ core.Message,_ []byte)error{ *sends++;return nil })
 id:=core.ID()
 raw:=[]byte("From: original@example.invalid\r\nTo: dest@example.invalid\r\n\r\nAccepted original\r\n")
 msg:=core.Message{ID:id,Sender:"original@example.invalid",Recipients:[]string{"dest@example.invalid"}}
 if err:=q.Enqueue(msg,raw);err!=nil{t.Fatal(err)}
 rec,err:=q.get(id);if err!=nil{t.Fatal(err)}
 rec.State="dead";rec.Attempts=MaxDeliveryAttempts;rec.Updated=time.Now().UTC()
 if err:=q.put(rec);err!=nil{t.Fatal(err)}
 return q,store,id,raw,sends
}

func TestOperatorRetryIsAuditedBeforeOriginalCanRelay(t *testing.T){
 q,store,id,raw,sends:=retryAuditFixture(t)
 if err:=q.RetryWithAudit(id,"Renée Operator");err!=nil{t.Fatal(err)}
 rec,err:=q.get(id);if err!=nil{t.Fatal(err)}
 if rec.State!="queued"||rec.Attempts!=0||!bytes.Equal(rec.RawRFC822,raw){t.Fatalf("retry changed original or schedule: %+v",rec.QueuedMessage)}
 msg,ok:=store.Get(id);if !ok||msg.Delivery!="retry_requested"{t.Fatalf("retry was not journaled: %+v",msg)}
 found:=false
 for _,f:=range msg.Findings{if f.Symbol=="QUEUE_RETRY_REQUESTED"&&f.Source=="manual/Renée Operator"{found=true}}
 if !found{t.Fatal("operator attribution missing from retry audit")}
 if err:=q.ProcessDue(context.Background());err!=nil{t.Fatal(err)}
 if *sends!=1{t.Fatalf("expected one relay after audit, got %d",*sends)}
 final,ok:=store.Get(id);if !ok||final.Delivery!="relayed"{t.Fatalf("relay history missing: %+v",final)}
 found=false
 for _,f:=range final.Findings{if f.Symbol=="QUEUE_RETRY_REQUESTED"{found=true}}
 if !found{t.Fatal("delivery finalization erased retry audit")}
}

func TestRetryJournalOutageDoesNotChangeOriginalOrSchedule(t *testing.T){
 q,_,id,_,sends:=retryAuditFixture(t)
 before,err:=os.ReadFile(q.path(id));if err!=nil{t.Fatal(err)}
 journal:=filepath.Join(filepath.Dir(q.dir),"events.jsonl")
 if err:=os.Mkdir(journal,0700);err!=nil{t.Fatal(err)}
 if err:=q.RetryWithAudit(id,"operator");err==nil||!strings.Contains(err.Error(),"audit"){t.Fatalf("journal outage did not prevent retry: %v",err)}
 after,err:=os.ReadFile(q.path(id))
 if err!=nil||!bytes.Equal(before,after){t.Fatalf("journal failure changed original: %v",err)}
 if *sends!=0{t.Fatal("relay occurred despite failed audit")}
}

func TestRetryActorValidationAndDiscardIntentFailClosed(t *testing.T){
 q,store,id,_,_:=retryAuditFixture(t)
 before,err:=os.ReadFile(q.path(id));if err!=nil{t.Fatal(err)}
 for _,actor:=range []string{"","admin\nforged","admin\u202eforged",strings.Repeat("x",129)}{
  if err:=q.RetryWithAudit(id,actor);err==nil{t.Fatalf("unsafe actor %q accepted",actor)}
 }
 msg:=core.Message{ID:id,Sender:"original@example.invalid",Recipients:[]string{"dest@example.invalid"},Delivery:"discard_requested"}
 if err:=store.Save(msg);err!=nil{t.Fatal(err)}
 if err:=q.RetryWithAudit(id,"operator");err==nil{t.Fatal("discard intent was replayable")}
 after,err:=os.ReadFile(q.path(id))
 if err!=nil||!bytes.Equal(before,after){t.Fatal("refused retry modified accepted original")}
}

func TestLegacyRetryRecordsUnattributedCompatibilityActor(t *testing.T){
 q,store,id,_,_:=retryAuditFixture(t)
 if err:=q.Retry(id);err!=nil{t.Fatal(err)}
 msg,ok:=store.Get(id);if !ok{t.Fatal("legacy retry did not write audit")}
 found:=false
 for _,f:=range msg.Findings{if f.Symbol=="QUEUE_RETRY_REQUESTED"&&strings.Contains(f.Source,"legacy API"){found=true}}
 if !found{t.Fatal("legacy retry bypassed audit")}
}

func TestRetryRefusesInFlightWithoutMutation(t *testing.T){
 q,_,id,_,_:=retryAuditFixture(t)
 rec,err:=q.get(id);if err!=nil{t.Fatal(err)}
 rec.State="delivering";if err:=q.put(rec);err!=nil{t.Fatal(err)}
 before,err:=os.ReadFile(q.path(id));if err!=nil{t.Fatal(err)}
 if err:=q.RetryWithAudit(id,"operator");err==nil{t.Fatal("in-flight original replayed")}
 after,err:=os.ReadFile(q.path(id))
 if err!=nil||!bytes.Equal(before,after){t.Fatal("in-flight refusal modified original")}
 if err:=q.RetryWithAudit("../invalid","operator");err==nil||errors.Is(err,os.ErrNotExist){t.Fatalf("invalid ID not rejected: %v",err)}
}
