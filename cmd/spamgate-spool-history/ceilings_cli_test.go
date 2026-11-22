package main

import (
 "bytes"
 "strings"
 "testing"
 "time"
)

func TestHistoryCLIAbsoluteQueueCeilingIncludesBaseline(t *testing.T) {
 dir:=t.TempDir()
 now:=time.Now().UTC()
 a:=writeReport(t,dir,"a.json",now.Add(-2*time.Minute),9)
 b:=writeReport(t,dir,"b.json",now.Add(-time.Minute),1)
 var out,errs bytes.Buffer
 code:=run([]string{"-report",a,"-report",b,"-max-queued-count","3"},&out,&errs)
 if code!=1{t.Fatalf("expected operational failure, got %d: %s",code,errs.String())}
 if !strings.Contains(out.String(),"sample_0: queued_count=9 exceeds max-queued-count=3"){t.Fatalf("baseline not enforced: %s",out.String())}
 out.Reset();errs.Reset()
 code=run([]string{"-report",a,"-report",b,"-max-queued-count","-2"},&out,&errs)
 if code!=2{t.Fatalf("expected invalid configuration, got %d",code)}
}
