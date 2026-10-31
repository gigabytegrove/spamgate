//go:build linux

package core

import (
 "os"
 "path/filepath"
 "sync"
 "testing"
 "time"
)

func TestIndependentStoresReconcileHistoryBeforeAppendAndCompact(t *testing.T){
 dir:=t.TempDir()
 a,err:=Open(dir);if err!=nil{t.Fatal(err)}
 b,err:=Open(dir);if err!=nil{t.Fatal(err)}
 first:=Message{ID:ID(),Timestamp:time.Now().UTC(),Action:"accept"}
 second:=Message{ID:ID(),Timestamp:time.Now().UTC(),Action:"tag"}
 if err:=a.Save(first);err!=nil{t.Fatal(err)}
 if err:=b.Save(second);err!=nil{t.Fatal(err)}
 if err:=a.Compact();err!=nil{t.Fatal(err)}
 recovered,err:=Open(dir);if err!=nil{t.Fatal(err)}
 if _,ok:=recovered.Get(first.ID);!ok{t.Fatal("first scan lost")}
 if _,ok:=recovered.Get(second.ID);!ok{t.Fatal("second scan lost during stale compaction")}
}
func TestIndependentStoreConcurrentJournalWriters(t *testing.T){
 dir:=t.TempDir()
 a,err:=Open(dir);if err!=nil{t.Fatal(err)}
 b,err:=Open(dir);if err!=nil{t.Fatal(err)}
 const count=20
 var wg sync.WaitGroup
 errs:=make(chan error,count)
 for i:=0;i<count;i++{
  wg.Add(1)
  go func(i int){
   defer wg.Done()
   s:=a;if i%2==1{s=b}
   errs<-s.Save(Message{ID:ID(),Timestamp:time.Now().UTC(),Action:"accept"})
  }(i)
 }
 wg.Wait();close(errs)
 for err:=range errs{if err!=nil{t.Fatal(err)}}
 c,err:=Open(dir);if err!=nil{t.Fatal(err)}
 if got:=len(c.List(100,""));got!=count{t.Fatalf("lost history: got %d want %d",got,count)}
}
func TestIndependentStoreRefusesCorruptExternalJournal(t *testing.T){
 dir:=t.TempDir()
 a,err:=Open(dir);if err!=nil{t.Fatal(err)}
 b,err:=Open(dir);if err!=nil{t.Fatal(err)}
 if err:=a.Save(Message{ID:ID(),Timestamp:time.Now().UTC(),Action:"accept"});err!=nil{t.Fatal(err)}
 path:=filepath.Join(dir,"events.jsonl")
 f,err:=os.OpenFile(path,os.O_APPEND|os.O_WRONLY,0600);if err!=nil{t.Fatal(err)}
 if _,err:=f.WriteString("{corrupt}\n");err!=nil{t.Fatal(err)}
 if err:=f.Close();err!=nil{t.Fatal(err)}
 before,err:=os.ReadFile(path);if err!=nil{t.Fatal(err)}
 if err:=b.Save(Message{ID:ID(),Action:"accept"});err==nil{t.Fatal("corrupt journal accepted")}
 after,err:=os.ReadFile(path);if err!=nil{t.Fatal(err)}
 if string(before)!=string(after){t.Fatal("corrupt evidence overwritten")}
}
func TestHistoryJournalLockRejectsSymlink(t *testing.T){
 dir:=t.TempDir()
 target:=filepath.Join(t.TempDir(),"victim")
 if err:=os.WriteFile(target,[]byte("preserve"),0600);err!=nil{t.Fatal(err)}
 if err:=os.Symlink(target,filepath.Join(dir,".events-journal.lock"));err!=nil{t.Fatal(err)}
 if _,err:=Open(dir);err==nil{t.Fatal("symlinked lock accepted")}
 b,err:=os.ReadFile(target);if err!=nil{t.Fatal(err)}
 if string(b)!="preserve"{t.Fatal("symlink target modified")}
}
