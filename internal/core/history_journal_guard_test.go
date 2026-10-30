package core

import(
 "context"
 "os"
 "path/filepath"
 "testing"
 "time"
)

func TestAppendRefusesMissingOrTruncatedJournalWithoutRecreating(t *testing.T) {
 for _, tc:=range []struct{name string;truncate bool}{{"deleted",false},{"truncated",true}}{
  t.Run(tc.name,func(t *testing.T){
   dir:=t.TempDir()
   store,e:=Open(dir);if e!=nil{t.Fatal(e)}
   msg:=Message{ID:ID(),Timestamp:time.Now().UTC(),Action:"accept"}
   if e:=store.Save(msg);e!=nil{t.Fatal(e)}
   path:=filepath.Join(dir,"events.jsonl")
   if tc.truncate {
    if e:=os.WriteFile(path,nil,0600);e!=nil{t.Fatal(e)}
   }else{
    if e:=os.Remove(path);e!=nil{t.Fatal(e)}
   }
   another:=Message{ID:ID(),Timestamp:time.Now().UTC(),Action:"tag"}
   if e:=store.Save(another);e==nil{t.Fatal("silently recreated/truncated loaded history journal")}
   if _,ok:=store.Get(another.ID);ok{t.Fatal("failed append inserted non-durable message")}
   if !tc.truncate {
    if _,e:=os.Stat(path);!os.IsNotExist(e){t.Fatalf("silently recreated journal: %v",e)}
   }else if b,e:=os.ReadFile(path);e!=nil||len(b)!=0{t.Fatal("truncated evidence overwritten")}
  })
 }
}

func TestDailyCompactRefusesCorruptOrTruncatedJournal(t *testing.T) {
 for _, corrupt:=range []bool{false,true}{
  t.Run(map[bool]string{false:"truncated",true:"corrupt"}[corrupt],func(t *testing.T){
   dir:=t.TempDir();store,e:=Open(dir);if e!=nil{t.Fatal(e)}
   msg:=Message{ID:ID(),Timestamp:time.Now().UTC(),Action:"accept"}
   if e:=store.Save(msg);e!=nil{t.Fatal(e)}
   path:=filepath.Join(dir,"events.jsonl")
   bad:=[]byte("{}\n")
   if corrupt{bad=[]byte("{malformed\n")}
   if e:=os.WriteFile(path,bad,0600);e!=nil{t.Fatal(e)}
   if e:=store.Compact();e==nil{t.Fatal("corrupt or missing journal was overwritten by compaction")}
   after,e:=os.ReadFile(path);if e!=nil||string(after)!=string(bad){t.Fatal("forensic evidence not preserved")}
  })
 }
}

func TestCompactPersistsAndPreservesHistoryAcrossRestart(t *testing.T){
 dir:=t.TempDir();s,e:=Open(dir);if e!=nil{t.Fatal(e)}
 msg:=Message{ID:ID(),Timestamp:time.Now().UTC(),Action:"accept"}
 if e:=s.Save(msg);e!=nil{t.Fatal(e)}
 if e:=s.Compact();e!=nil{t.Fatal(e)}
 reopened,e:=Open(dir);if e!=nil{t.Fatal(e)}
 got,ok:=reopened.Get(msg.ID);if !ok||got.Action!="accept"{t.Fatalf("compacted scan unavailable: %+v",got)}
 if e:=reopened.Compact();e!=nil{t.Fatal(e)}
 audit,e:=reopened.AuditHistory(context.Background());if e!=nil{t.Fatal(e)}
 if audit.Status!="ok"||audit.UniqueScanIDs!=1{t.Fatalf("recovery audit: %+v",audit)}
}
