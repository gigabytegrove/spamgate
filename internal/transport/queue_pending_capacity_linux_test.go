//go:build linux

package transport

import (
 "context"
 "fmt"
 "os"
 "path/filepath"
 "strings"
 "testing"
 "github.com/gigabytegrove/spamgate/internal/core"
)

func pendingTestMessage() core.Message {
 return core.Message{ID:core.ID(),Sender:"sender@example.org",Recipients:[]string{"recipient@example.net"}}
}

func TestPendingOriginalCountReservesIntakeCapacity(t *testing.T) {
 q,_,_:=newIntegrityQueue(t)
 for i:=0;i<MaxQueueJobs;i++ {
  if err:=os.WriteFile(filepath.Join(q.dir,fmt.Sprintf(".pending-%04d",i)),[]byte("retained"),0600);err!=nil{t.Fatal(err)}
 }
 s,err:=q.Snapshot()
 if err!=nil || s.PendingTemps!=MaxQueueJobs {t.Fatalf("pending inventory %+v %v",s,err)}
 if err:=q.Enqueue(pendingTestMessage(),[]byte("Subject: refusal\r\n\r\nbody"));err==nil||!strings.Contains(err.Error(),"capacity"){t.Fatalf("intake accepted pending saturation: %v",err)}
}

func TestPendingOriginalBytesReserveIntakeCapacity(t *testing.T) {
 q,_,_:=newIntegrityQueue(t)
 for i:=0;i<27;i++ {
  f,err:=os.OpenFile(filepath.Join(q.dir,fmt.Sprintf(".pending-sparse-%04d",i)),os.O_CREATE|os.O_EXCL|os.O_WRONLY,0600)
  if err!=nil{t.Fatal(err)}
  if err:=f.Truncate(20<<20);err!=nil{f.Close();t.Fatal(err)}
  if err:=f.Close();err!=nil{t.Fatal(err)}
 }
 s,err:=q.Snapshot()
 if err!=nil||s.PendingTempBytes<=MaxQueueBytes{t.Fatalf("pending bytes %+v %v",s,err)}
 if err:=q.Enqueue(pendingTestMessage(),[]byte("Subject: refusal\r\n\r\nbody"));err==nil||!strings.Contains(err.Error(),"capacity"){t.Fatalf("intake accepted pending bytes: %v",err)}
}

func TestHardlinkedOriginalRefusesDeliveryAndRecovers(t *testing.T) {
 sends:=0
 q,_,_:=newRecoveryQueue(t,func(context.Context,core.Message,[]byte)error{sends++;return nil})
 msg:=pendingTestMessage()
 if err:=q.Enqueue(msg,[]byte("Subject: original\r\n\r\nbody"));err!=nil{t.Fatal(err)}
 alias:=filepath.Join(t.TempDir(),"alias")
 if err:=os.Link(q.path(msg.ID),alias);err!=nil{t.Fatal(err)}
 if _,err:=q.Snapshot();err==nil||!strings.Contains(err.Error(),"hard link"){t.Fatalf("accepted hardlink: %v",err)}
 if err:=q.ProcessDue(context.Background());err==nil||sends!=0{t.Fatalf("unsafe delivery %v %d",err,sends)}
 if err:=os.Remove(alias);err!=nil{t.Fatal(err)}
 if err:=q.ProcessDue(context.Background());err!=nil||sends!=1{t.Fatalf("repair failed %v %d",err,sends)}
}

func TestExposedOriginalRefusesDeliveryAndRecovers(t *testing.T) {
 sends:=0
 q,_,_:=newRecoveryQueue(t,func(context.Context,core.Message,[]byte)error{sends++;return nil})
 msg:=pendingTestMessage()
 if err:=q.Enqueue(msg,[]byte("Subject: original\r\n\r\nbody"));err!=nil{t.Fatal(err)}
 if err:=os.Chmod(q.path(msg.ID),0644);err!=nil{t.Fatal(err)}
 if _,err:=q.Snapshot();err==nil||!strings.Contains(err.Error(),"private"){t.Fatalf("accepted exposed original: %v",err)}
 if err:=q.ProcessDue(context.Background());err==nil||sends!=0{t.Fatalf("unsafe delivery %v %d",err,sends)}
 if err:=os.Chmod(q.path(msg.ID),0600);err!=nil{t.Fatal(err)}
 if err:=q.ProcessDue(context.Background());err!=nil||sends!=1{t.Fatalf("repair failed %v %d",err,sends)}
}

func TestHardlinkedPendingEvidenceRefusesIntake(t *testing.T) {
 q,_,_:=newIntegrityQueue(t)
 path:=filepath.Join(q.dir,".pending-alias")
 if err:=os.WriteFile(path,[]byte("original evidence"),0600);err!=nil{t.Fatal(err)}
 alias:=filepath.Join(t.TempDir(),"alias")
 if err:=os.Link(path,alias);err!=nil{t.Fatal(err)}
 if _,err:=q.Snapshot();err==nil||!strings.Contains(err.Error(),"hard link"){t.Fatalf("accepted pending alias: %v",err)}
 if err:=q.Enqueue(pendingTestMessage(),[]byte("Subject: refused\r\n\r\nbody"));err==nil{t.Fatal("accepted unsafe pending evidence")}
 if err:=os.Remove(alias);err!=nil{t.Fatal(err)}
 if _,err:=q.Snapshot();err!=nil{t.Fatalf("repair failed: %v",err)}
}

func TestPutRefusesSymlinkDestinationAndPreservesEvidence(t *testing.T) {
 q,_,_:=newIntegrityQueue(t)
 msg:=pendingTestMessage()
 if err:=q.Enqueue(msg,[]byte("Subject: original\r\n\r\nbody"));err!=nil{t.Fatal(err)}
 rec,err:=q.get(msg.ID);if err!=nil{t.Fatal(err)}
 saved:=filepath.Join(t.TempDir(),"original.json")
 if err:=os.Rename(q.path(msg.ID),saved);err!=nil{t.Fatal(err)}
 victim:=filepath.Join(t.TempDir(),"victim")
 if err:=os.WriteFile(victim,[]byte("unchanged"),0600);err!=nil{t.Fatal(err)}
 if err:=os.Symlink(victim,q.path(msg.ID));err!=nil{t.Fatal(err)}
 if err:=q.put(rec);err==nil||!strings.Contains(err.Error(),"unpublished spool retained"){t.Fatalf("unsafe replacement: %v",err)}
 b,err:=os.ReadFile(victim);if err!=nil||string(b)!="unchanged"{t.Fatalf("victim changed %q %v",b,err)}
 if _,err:=os.Stat(saved);err!=nil{t.Fatal(err)}
}
