package main

import (
 "bytes"
 "strings"
 "testing"

 "github.com/gigabytegrove/spamgate/internal/spoolaudit"
)

func TestDeadAgeLimit(t *testing.T) {
 report:=spoolaudit.Report{OldestDeadSeconds:3601}
 for _,tc:=range []struct{limit int64;fail bool}{
  {-1,false},{3601,false},{3600,true},{0,true},
 } {
  got:=deliveryAgeFailures(report,-1,-1,tc.limit)
  if (len(got)>0)!=tc.fail {t.Fatalf("limit %d failures %v",tc.limit,got)}
  if tc.fail && !strings.Contains(got[0],"dead_age_seconds=3601") {t.Fatalf("unexpected failure: %v",got)}
 }
}

func TestDeadAgeCLIRejectsInvalidLimit(t *testing.T) {
 var out,err bytes.Buffer
 if code:=run([]string{"-max-dead-age-seconds=-2"},&out,&err);code!=2 {t.Fatalf("code=%d stderr=%s",code,err.String())}
}
