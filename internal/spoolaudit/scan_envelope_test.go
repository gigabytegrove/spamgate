package spoolaudit

import (
 "encoding/json"
 "os"
 "path/filepath"
 "strings"
 "testing"
)

func TestAuditRejectsCrossRecipientSignedScan(t *testing.T) {
 for _,tc:=range []struct{name,scan string; wantBad bool}{
  {"matching",`{"id":"0123456789abcdef0123456789abcdef","sender":"sender@example.test","recipients":["a@example.test"]}`,false},
  {"other recipient",`{"id":"0123456789abcdef0123456789abcdef","sender":"sender@example.test","recipients":["b@example.test"]}`,true},
  {"other sender",`{"id":"0123456789abcdef0123456789abcdef","sender":"other@example.test","recipients":["a@example.test"]}`,true},
  {"other id",`{"id":"ffffffffffffffffffffffffffffffff","sender":"sender@example.test","recipients":["a@example.test"]}`,true},
  {"malformed scan type",`"not an object"`,true},
  {"legacy absent",`null`,false},
 } {
  t.Run(tc.name,func(t *testing.T){
   dir:=privateDir(t)
   r:=record{
    ID:"0123456789abcdef0123456789abcdef",
    Sender:"sender@example.test",
    Recipients:[]string{"a@example.test"},
    Raw:[]byte("Subject: test\\r\\n\\r\\nbody"),
    State:"queued",Size:21,
    Scan:json.RawMessage(tc.scan),
   }
   r.Size=len(r.Raw)
   r.IntegritySHA256=immutableDigest(r)
   r.StateSHA256=stateDigest(r)
   b,err:=json.Marshal(r);if err!=nil{t.Fatal(err)}
   path:=filepath.Join(dir,r.ID+".json")
   if err:=os.WriteFile(path,b,0600);err!=nil{t.Fatal(err)}
   _,err=readRecord(path)
   if tc.wantBad {
    if err==nil || !strings.Contains(err.Error(),"scan envelope"){t.Fatalf("unsafe signed scan accepted: %v",err)}
   } else if err!=nil {t.Fatalf("valid record rejected: %v",err)}
   report,auditErr:=Audit(dir)
   if auditErr!=nil {t.Fatal(auditErr)}
   if tc.wantBad && (report.UnreadableRecords!=1 || report.FindingCounts["unreadable_record"]!=1) {
    t.Fatalf("audit missed scan mismatch: %+v",report)
   }
   if !tc.wantBad && report.UnreadableRecords!=0 {t.Fatalf("clean scan reported unreadable: %+v",report)}
  })
 }
}
