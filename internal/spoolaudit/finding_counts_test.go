package spoolaudit

import (
 "encoding/json"
 "os"
 "path/filepath"
 "strconv"
 "strings"
 "testing"
)

// Detailed evidence is capped, but the complete per-code totals must remain
// available for diagnostics and alert thresholds. Neither path nor mail data
// should be embedded in the count keys.
func TestAuditFindingCountsSurviveTruncation(t *testing.T) {
 dir:=privateDir(t)
 for i:=0;i<maxFindings+7;i++ {
  name:=filepath.Join(dir,"bad-"+strconv.Itoa(i)+".json")
  if err:=os.WriteFile(name,[]byte("{}"),0600);err!=nil {t.Fatal(err)}
 }
 report,err:=Audit(dir)
 if err==nil || !strings.Contains(err.Error(),"finding limit exceeded") {t.Fatalf("expected incomplete audit: %v",err)}
 if got:=report.FindingCounts["invalid_filename"];got!=maxFindings+7 {
  t.Fatalf("lost invalid filename count: %d",got)
 }
 if report.DroppedFindings!=7 || len(report.Findings)!=maxFindings {
  t.Fatalf("unexpected evidence limits: retained=%d dropped=%d",len(report.Findings),report.DroppedFindings)
 }
 total:=0
 for _,count:=range report.FindingCounts {total+=count}
 if total!=len(report.Findings)+report.DroppedFindings {
  t.Fatalf("per-code counts %d do not match total findings %d",total,len(report.Findings)+report.DroppedFindings)
 }
 data,err:=json.Marshal(report)
 if err!=nil {t.Fatal(err)}
 var decoded struct {FindingCounts map[string]int `json:"finding_counts"`}
 if err:=json.Unmarshal(data,&decoded);err!=nil {t.Fatal(err)}
 if decoded.FindingCounts["invalid_filename"]!=maxFindings+7 {t.Fatal("JSON lost complete count")}
}

func TestAuditFindingCountsAcrossCodesAndCleanQueue(t *testing.T) {
 dir:=privateDir(t)
 write(t,dir,idA+".json",fixture(idA))
 clean,err:=Audit(dir)
 if err!=nil {t.Fatal(err)}
 if clean.FindingCounts==nil || len(clean.FindingCounts)!=0 {t.Fatalf("clean report: %+v",clean.FindingCounts)}
 if err:=os.WriteFile(filepath.Join(dir,"bad-name.json"),[]byte("{}"),0600);err!=nil {t.Fatal(err)}
 if err:=os.WriteFile(filepath.Join(dir,idB+".json"),[]byte("{}"),0600);err!=nil {t.Fatal(err)}
 report,err:=Audit(dir)
 if err!=nil {t.Fatal(err)}
 if report.FindingCounts["invalid_filename"]!=1 || report.FindingCounts["unreadable_record"]!=1 {
  t.Fatalf("per-code totals: %+v",report.FindingCounts)
 }
 if len(report.Findings)!=2 || report.DroppedFindings!=0 {t.Fatalf("unexpected findings: %+v",report)}
}
