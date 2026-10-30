package transport

import (
 "context"
 "os"
 "path/filepath"
 "strings"
 "testing"

 "github.com/gigabytegrove/spamgate/internal/core"
)

func TestSpoolReadRejectsReplacedFileBeforeReading(t *testing.T) {
 dir:=t.TempDir()
 path:=filepath.Join(dir,"queue.json")
 if err:=os.WriteFile(path,[]byte("original"),0600);err!=nil{t.Fatal(err)}
 inspected,err:=os.Lstat(path);if err!=nil{t.Fatal(err)}
 replacement:=filepath.Join(dir,"replacement")
 if err:=os.WriteFile(replacement,[]byte("new contents"),0600);err!=nil{t.Fatal(err)}
 if err:=os.Rename(replacement,path);err!=nil{t.Fatal(err)}
 if _,err:=readSpoolFile(path,inspected);err==nil||!strings.Contains(err.Error(),"changed between inspection"){
  t.Fatalf("read changed inode after lstat: %v",err)
 }
}

func TestSpoolReadRejectsSymlinkReplacementBeforeReading(t *testing.T) {
 dir:=t.TempDir()
 path:=filepath.Join(dir,"queue.json")
 target:=filepath.Join(dir,"private-original")
 if err:=os.WriteFile(path,[]byte("original"),0600);err!=nil{t.Fatal(err)}
 if err:=os.WriteFile(target,[]byte("private contents"),0600);err!=nil{t.Fatal(err)}
 inspected,err:=os.Lstat(path);if err!=nil{t.Fatal(err)}
 if err:=os.Remove(path);err!=nil{t.Fatal(err)}
 if err:=os.Symlink(target,path);err!=nil{t.Skipf("symlinks unavailable: %v",err)}
 if _,err:=readSpoolFile(path,inspected);err==nil{
  t.Fatal("read symlink target after inspected record was replaced")
 }
}

func TestSpoolReadRejectsOversizedAndShortRecords(t *testing.T) {
 dir:=t.TempDir()
 path:=filepath.Join(dir,"queue.json")
 for _,size:=range []int{0,1,(20<<20)+1}{
  if err:=os.WriteFile(path,make([]byte,size),0600);err!=nil{t.Fatal(err)}
  inspected,err:=os.Lstat(path);if err!=nil{t.Fatal(err)}
  if _,err:=readSpoolFile(path,inspected);err==nil{
   t.Fatalf("accepted invalid queue file size %d",size)
  }
 }
}

func TestQueueSymlinkedJobFailsClosedBeforeDelivery(t *testing.T) {
 q,_,_:=newIntegrityQueue(t)
 id:=core.ID()
 m:=core.Message{ID:id,Sender:"sender@example.org",Recipients:[]string{"recipient@example.net"}}
 if err:=q.Enqueue(m,[]byte("Subject: test\r\n\r\nOriginal"));err!=nil{t.Fatal(err)}
 path:=q.path(id)
 target:=filepath.Join(t.TempDir(),"original.json")
 original,err:=os.ReadFile(path);if err!=nil{t.Fatal(err)}
 if err:=os.WriteFile(target,original,0600);err!=nil{t.Fatal(err)}
 if err:=os.Remove(path);err!=nil{t.Fatal(err)}
 if err:=os.Symlink(target,path);err!=nil{t.Skipf("symlinks unavailable: %v",err)}
 if _,err:=q.Snapshot();err==nil{t.Fatal("accepted symlinked queue job")}
 if err:=q.ProcessDue(context.Background());err==nil{t.Fatal("attempted processing symlinked job")}
}
