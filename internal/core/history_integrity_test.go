package core

import (
 "context"
 "os"
 "path/filepath"
 "strings"
 "testing"
 "time"
)

func TestAuditHistoryMatchesJournalAndDoesNotMutate(t *testing.T) {
 dir:=t.TempDir()
 s,err:=Open(dir);if err!=nil{t.Fatal(err)}
 m:=Message{ID:ID(),Timestamp:time.Now().UTC(),Sender:"sensitive@example.org",Recipients:[]string{"private@example.org"},Subject:"confidential",Action:"accept"}
 if err:=s.Save(m);err!=nil{t.Fatal(err)}
 path:=filepath.Join(dir,"events.jsonl")
 before,err:=os.ReadFile(path);if err!=nil{t.Fatal(err)}
 result,err:=s.AuditHistory(context.Background());if err!=nil{t.Fatal(err)}
 if result.Status!="ok"||!result.FilePresent||result.DiskEvents!=1||result.LoadedRetained!=1||result.MissingRetained!=0||len(result.SHA256)!=64{
  t.Fatalf("incorrect audit %+v",result)
 }
 if strings.Contains(result.Detail,"sensitive")||strings.Contains(result.Detail,"confidential"){t.Fatal("mail contents leaked")}
 after,err:=os.ReadFile(path);if err!=nil||string(after)!=string(before){t.Fatal("read-only audit modified history")}
}

func TestAuditHistoryDetectsMissingCorruptAndTruncatedEvidence(t *testing.T) {
 dir:=t.TempDir();s,err:=Open(dir);if err!=nil{t.Fatal(err)}
 missing,_:=s.AuditHistory(context.Background())
 if missing.Status!="missing"||missing.LoadedRetained!=0{t.Fatalf("initial audit %+v",missing)}
 m:=Message{ID:ID(),Timestamp:time.Now().UTC(),Action:"quarantine"}
 if err:=s.Save(m);err!=nil{t.Fatal(err)}
 path:=filepath.Join(dir,"events.jsonl")
 if err:=os.WriteFile(path,[]byte(""),0600);err!=nil{t.Fatal(err)}
 mismatch,_:=s.AuditHistory(context.Background())
 if mismatch.Status!="mismatch"||mismatch.MissingRetained!=1{t.Fatalf("truncated audit %+v",mismatch)}
 if err:=os.WriteFile(path,[]byte("{broken\n"),0600);err!=nil{t.Fatal(err)}
 corrupt,_:=s.AuditHistory(context.Background())
 if corrupt.Status!="corrupt"{t.Fatalf("corruption not detected %+v",corrupt)}
 if err:=os.Remove(path);err!=nil{t.Fatal(err)}
 lost,_:=s.AuditHistory(context.Background())
 if lost.Status!="mismatch"||lost.MissingRetained!=1{t.Fatalf("missing retained audit %+v",lost)}
}

func TestAuditHistoryRepeatedEventKeepsLatestAndHonorsContext(t *testing.T) {
 dir:=t.TempDir();s,err:=Open(dir);if err!=nil{t.Fatal(err)}
 m:=Message{ID:ID(),Timestamp:time.Now().UTC(),Action:"accept"}
 if err:=s.Save(m);err!=nil{t.Fatal(err)}
 m.Action="tag";if err:=s.Save(m);err!=nil{t.Fatal(err)}
 ok,_:=s.AuditHistory(context.Background())
 if ok.Status!="ok"||ok.DiskEvents!=2||ok.UniqueScanIDs!=1||ok.LoadedRetained!=1{t.Fatalf("revisions %+v",ok)}
 ctx,cancel:=context.WithCancel(context.Background());cancel()
 if _,err:=s.AuditHistory(ctx);err==nil{t.Fatal("cancelled audit succeeded")}
}
