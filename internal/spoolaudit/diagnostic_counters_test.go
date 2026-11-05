package spoolaudit

import (
 "os"
 "path/filepath"
 "strings"
 "testing"
)

// Diagnostic counters must describe the full scan, including findings omitted
// from the bounded details array. A malformed published name is not opened.
func TestAuditDiagnosticCountersBeyondFindingLimit(t *testing.T) {
 dir := privateDir(t)
 for i:=0; i<maxFindings+5; i++ {
  name:=filepath.Join(dir,"invalid-"+strings.Repeat("x",i%20)+"-"+itoaAuditTest(i)+".json")
  if err:=os.WriteFile(name,[]byte("{}"),0600);err!=nil {t.Fatal(err)}
 }
 report,err:=Audit(dir)
 if err==nil {t.Fatal("expected incomplete findings error")}
 if report.InvalidFilenames!=maxFindings+5 || report.UnreadableRecords!=0 {
  t.Fatalf("aggregate counters lost findings: %+v",report)
 }
 if report.DroppedFindings!=5 || !strings.Contains(report.Explain(),"invalid_filenames=517") {
  t.Fatalf("operator summary lost evidence: %s",report.Explain())
 }
}

func TestAuditUnreadableRecordCountAndSummary(t *testing.T) {
 dir:=privateDir(t)
 for _,id:=range []string{
  "00000000000000000000000000000001",
  "00000000000000000000000000000002",
 } {
  if err:=os.WriteFile(filepath.Join(dir,id+".json"),[]byte("{}"),0600);err!=nil {t.Fatal(err)}
 }
 report,err:=Audit(dir)
 if err!=nil {t.Fatal(err)}
 if report.UnreadableRecords!=2 || report.InvalidFilenames!=0 {
  t.Fatalf("unexpected diagnostic counters: %+v",report)
 }
 if !strings.Contains(report.Explain(),"unreadable_records=2") {
  t.Fatalf("missing unreadable count in summary: %s",report.Explain())
 }
}

func itoaAuditTest(n int) string {
 if n==0{return "0"}
 var buf [20]byte
 i:=len(buf)
 for n>0 {i--;buf[i]=byte('0'+n%10);n/=10}
 return string(buf[i:])
}
