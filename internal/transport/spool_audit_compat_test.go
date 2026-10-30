package transport

import (
 "context"
 "encoding/json"
 "os"
 "path/filepath"
 "testing"

 "github.com/gigabytegrove/spamgate/internal/core"
 "github.com/gigabytegrove/spamgate/internal/spoolaudit"
)
// The read-only auditor must recognize the exact wire format produced
// by the real delivery queue, including the persisted scan metadata digest.
func TestStandaloneSpoolAuditRecognizesNativeQueueRecord(t *testing.T){
 dir:=t.TempDir()
 store,err:=core.Open(dir);if err!=nil{t.Fatal(err)}
 q,err:=NewDeliveryQueue(dir,store,func(context.Context,core.Message,[]byte)error{return nil})
 if err!=nil{t.Fatal(err)}
 id:=core.ID()
 msg:=core.Message{ID:id,Sender:"sender@example.invalid",Recipients:[]string{"recipient@example.invalid"},Subject:"native test"}
 if err:=q.Enqueue(msg,[]byte("Subject: native test\r\n\r\nbody"));err!=nil{t.Fatal(err)}
 report,err:=spoolaudit.Audit(filepath.Join(dir,"delivery-queue"))
 if err!=nil||report.HasFindings()||report.Published!=1||report.States["queued"]!=1{
  t.Fatalf("native queue and auditor digests disagree: %+v %v",report,err)
 }
 path:=q.path(id)
 b,err:=os.ReadFile(path);if err!=nil{t.Fatal(err)}
 var rec spoolRecord
 if err:=json.Unmarshal(b,&rec);err!=nil{t.Fatal(err)}
 rec.Sender="tampered@example.invalid"
 b,err=json.Marshal(rec);if err!=nil{t.Fatal(err)}
 if err:=os.WriteFile(path,b,0600);err!=nil{t.Fatal(err)}
 report,err=spoolaudit.Audit(filepath.Join(dir,"delivery-queue"))
 if err!=nil||!report.HasFindings(){t.Fatalf("auditor missed tampered envelope: %+v %v",report,err)}
}
