package spoolaudit

import (
 "bytes"
 "encoding/json"
 "os"
 "path/filepath"
 "strings"
 "testing"
)

func TestAuditLifecycleFindingIsReadOnlyAndPrivate(t *testing.T){
 dir:=privateDir(t)
 rec:=fixture(idA)
 rec.State="delivered";rec.Attempts=0;rec.DeliveredAt=rec.Created.Add(-1)
 rec.StateSHA256=stateDigest(rec)
 write(t,dir,idA+".json",rec)
 path:=filepath.Join(dir,idA+".json")
 before,err:=os.ReadFile(path);if err!=nil{t.Fatal(err)}
 report,err:=Audit(dir)
 if err!=nil||report.LifecycleAnomalies!=1||!hasCode(report,"unproven_delivery_state")||!report.HasFindings(){
  t.Fatalf("unsafe lifecycle not surfaced: %+v %v",report,err)
 }
 after,err:=os.ReadFile(path)
 if err!=nil||!bytes.Equal(before,after){t.Fatal("forensic audit changed accepted original")}
 output,err:=json.Marshal(report);if err!=nil{t.Fatal(err)}
 for _,secret:=range []string{"sensitive@example.invalid","secret@example.invalid","Confidential"}{
  if strings.Contains(string(output),secret){t.Fatalf("report leaked %s",secret)}
 }
 if !strings.Contains(report.Explain(),"lifecycle_anomalies=1"){t.Fatal("text summary omitted anomaly count")}
}
func TestAuditScanEnvelopeMismatchDoesNotRewriteOriginal(t *testing.T){
 dir:=privateDir(t)
 rec:=fixture(idA)
 rec.Scan=[]byte(`{"id":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","sender":"sensitive@example.invalid","recipients":["secret@example.invalid"]}`)
 rec.IntegritySHA256=immutableDigest(rec)
 rec.StateSHA256=stateDigest(rec)
 write(t,dir,idA+".json",rec)
 report,err:=Audit(dir)
 if err!=nil||!hasCode(report,"scan_envelope_mismatch")||report.LifecycleAnomalies!=1{
  t.Fatalf("scan mismatch not surfaced: %+v %v",report,err)
 }
 if _,err:=os.Stat(filepath.Join(dir,idA+".json"));err!=nil{t.Fatal(err)}
}
func TestAuditThreePendingOriginalsClassifiesRepeatOfSecondAsDuplicate(t *testing.T){
 dir:=privateDir(t)
 first:=fixture(idA)
 second:=fixture(idA)
 second.Sender="different@example.invalid"
 second.IntegritySHA256=immutableDigest(second)
 second.StateSHA256=stateDigest(second)
 write(t,dir,".pending-a",first)
 write(t,dir,".pending-b",second)
 write(t,dir,".pending-c",second)
 report,err:=Audit(dir)
 if err!=nil||report.PendingDuplicateIDs!=2||report.PendingConflictingIDs!=1||
  !hasCode(report,"pending_duplicate")||!hasCode(report,"pending_id_collision"){
  t.Fatalf("incorrect unique-original collision accounting: %+v %v",report,err)
 }
}
