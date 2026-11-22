package main

import (
 "bytes"
 "encoding/json"
 "os"
 "path/filepath"
 "strings"
 "testing"
 "time"
)

func writeReport(t *testing.T,dir,name string,at time.Time,queued int) string {
 t.Helper()
 path:=filepath.Join(dir,name)
 report:=map[string]any{
  "captured_at":at.UTC().Format(time.RFC3339Nano),
  "gate_passed":true,"gate_failures":[]string{},
  "examined":queued,"published":queued,"pending":0,
  "states":map[string]int{"queued":queued},"findings":[]string{},"truncated":false,
 }
 raw,err:=json.Marshal(report);if err!=nil{t.Fatal(err)}
 if err:=os.WriteFile(path,raw,0600);err!=nil{t.Fatal(err)}
 return path
}

func TestHistoryCLIReportsIntermediateFailure(t *testing.T) {
 dir:=t.TempDir()
 now:=time.Now().UTC()
 a:=writeReport(t,dir,"a.json",now.Add(-3*time.Minute),1)
 b:=writeReport(t,dir,"b.json",now.Add(-2*time.Minute),10)
 c:=writeReport(t,dir,"c.json",now.Add(-time.Minute),1)
 var out,errs bytes.Buffer
 code:=run([]string{"-report",a,"-report",b,"-report",c,"-max-queue-growth","2","-max-snapshot-gap","2m"},&out,&errs)
 if code!=1 {t.Fatalf("code=%d stderr=%s",code,errs.String())}
 if !strings.Contains(out.String(),"\"failed_intervals\": 1") || !strings.Contains(out.String(),"interval_1") {t.Fatalf("missing transient evidence: %s",out.String())}
}

func TestHistoryCLIRefusesAliasedReports(t *testing.T) {
 dir:=t.TempDir()
 a:=writeReport(t,dir,"a.json",time.Now().UTC().Add(-time.Minute),1)
 alias:=filepath.Join(dir,"alias.json")
 if err:=os.Link(a,alias);err!=nil{t.Skipf("hard links unsupported: %v",err)}
 var out,errs bytes.Buffer
 if code:=run([]string{"-report",a,"-report",alias},&out,&errs);code!=2 {t.Fatalf("code=%d stderr=%s",code,errs.String())}
}

func TestHistoryCLIRejectsMissingReports(t *testing.T) {
 var out,errs bytes.Buffer
 if code:=run([]string{"-report","one"},&out,&errs);code!=2 {t.Fatalf("code=%d",code)}
}
