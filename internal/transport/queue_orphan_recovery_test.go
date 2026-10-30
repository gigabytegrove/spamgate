package transport

import (
 "context"
 "os"
 "path/filepath"
 "strings"
 "testing"

 "github.com/gigabytegrove/spamgate/internal/core"
)

func TestUnpublishedSpoolFilesSurviveRestartAndAreVisible(t *testing.T) {
 dir:=t.TempDir()
 store,err:=core.Open(dir);if err!=nil{t.Fatal(err)}
 delivered:=0
 sender:=func(context.Context,core.Message,[]byte)error{delivered++;return nil}
 q,err:=NewDeliveryQueue(dir,store,sender);if err!=nil{t.Fatal(err)}
 id:=core.ID()
 if err:=q.Enqueue(core.Message{ID:id,Sender:"sender@example.invalid",Recipients:[]string{"recipient@example.invalid"}},[]byte("Subject: retained\r\n\r\nbody"));err!=nil{t.Fatal(err)}
 orphan:=filepath.Join(dir,"delivery-queue",".pending-crash")
 if err:=os.WriteFile(orphan,[]byte("unpublished original retained for investigation"),0600);err!=nil{t.Fatal(err)}
 restarted,err:=NewDeliveryQueue(dir,store,sender);if err!=nil{t.Fatal(err)}
 summary,err:=restarted.Snapshot();if err!=nil{t.Fatal(err)}
 if summary.Total!=1||summary.PendingTemps!=1||summary.PendingTempBytes!=int64(len("unpublished original retained for investigation")){
  t.Fatalf("incomplete queue evidence: %+v",summary)
 }
 if err:=restarted.ProcessDue(context.Background());err!=nil{t.Fatal(err)}
 if delivered!=1{t.Fatalf("expected one normal delivery, got %d",delivered)}
 summary,err=restarted.Snapshot();if err!=nil{t.Fatal(err)}
 if summary.Total!=0||summary.PendingTemps!=1{t.Fatalf("lost orphaned evidence or retained delivered job: %+v",summary)}
 if b,err:=os.ReadFile(orphan);err!=nil||!strings.Contains(string(b),"unpublished original"){
  t.Fatalf("orphan original removed or changed: %v",err)
 }
}

func TestUnpublishedSpoolSymlinkFailsClosed(t *testing.T) {
 dir:=t.TempDir()
 store,err:=core.Open(dir);if err!=nil{t.Fatal(err)}
 q,err:=NewDeliveryQueue(dir,store,func(context.Context,core.Message,[]byte)error{return nil});if err!=nil{t.Fatal(err)}
 outside:=filepath.Join(dir,"outside")
 if err:=os.WriteFile(outside,[]byte("private"),0600);err!=nil{t.Fatal(err)}
 if err:=os.Symlink(outside,filepath.Join(q.dir,".pending-forged"));err!=nil{t.Skip(err)}
 if _,err:=q.Snapshot();err==nil{t.Fatal("accepted symlinked unpublished spool object")}
 if _,err:=NewDeliveryQueue(dir,store,func(context.Context,core.Message,[]byte)error{return nil});err==nil{t.Fatal("started with forged unpublished spool object")}
}

func TestUnpublishedSpoolOversizeFailsClosed(t *testing.T) {
 q,_,_:=newIntegrityQueue(t)
 f,err:=os.Create(filepath.Join(q.dir,".pending-oversized"));if err!=nil{t.Fatal(err)}
 if err:=f.Truncate((20<<20)+1);err!=nil{f.Close();t.Fatal(err)}
 if err:=f.Close();err!=nil{t.Fatal(err)}
 if _,err:=q.Snapshot();err==nil{t.Fatal("accepted oversized unpublished spool object")}
}
