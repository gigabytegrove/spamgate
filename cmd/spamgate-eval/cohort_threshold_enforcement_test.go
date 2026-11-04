package main

import (
 "bytes"
 "os"
 "path/filepath"
 "strings"
 "testing"
)

func TestExplicitCohortAcceptanceThresholdsRequireCohortGate(t *testing.T) {
 path:=filepath.Join(t.TempDir(),"labels.jsonl")
 if err:=os.WriteFile(path,[]byte("{\"label\":\"ham\",\"action\":\"accept\"}\n{\"label\":\"spam\",\"action\":\"reject\"}\n"),0600);err!=nil{t.Fatal(err)}
 cases:=[]string{
  "--min-cohort-ham=1",
  "--min-cohort-spam=1",
  "--max-cohort-fpr-upper=1",
  "--max-cohort-fpr-upper=0",
  "--min-cohort-recall-lower=0",
  "--min-cohort-recall-lower=1",
  "--min-cohort-precision-lower=0.5",
 }
 for _,arg:=range cases{
  t.Run(arg,func(t *testing.T){
   var out,stderr bytes.Buffer
   code:=run([]string{arg,"--min-ham=1","--min-spam=1",path},&out,&stderr)
   if code!=2 {t.Fatalf("unenforced threshold accepted: code=%d stderr=%s",code,stderr.String())}
   if out.Len()!=0 {t.Fatalf("partial/misleading report emitted: %s",out.String())}
   if !strings.Contains(stderr.String(),"--require-cohorts") || !strings.Contains(stderr.String(),strings.SplitN(arg,"=",2)[0]){
    t.Fatalf("missing actionable error: %s",stderr.String())
   }
  })
 }
}

func TestDisabledPrecisionAndDefaultCohortThresholdsRemainReportOnly(t *testing.T) {
 path:=filepath.Join(t.TempDir(),"labels.jsonl")
 if err:=os.WriteFile(path,[]byte("{\"label\":\"ham\",\"action\":\"accept\"}\n{\"label\":\"spam\",\"action\":\"reject\"}\n"),0600);err!=nil{t.Fatal(err)}
 var out,stderr bytes.Buffer
 code:=run([]string{"--min-cohort-precision-lower=0","--min-ham=1","--min-spam=1","--max-fpr-upper=1","--min-recall-lower=0",path},&out,&stderr)
 if code!=0 {t.Fatalf("default/report-only cohort configuration rejected: %d %s",code,stderr.String())}
 if !strings.Contains(out.String(),"\"gate_passed\":true"){t.Fatalf("unexpected result: %s",out.String())}
}

func TestCohortThresholdWithRequiredGateProducesMeasuredFailure(t *testing.T) {
 path:=filepath.Join(t.TempDir(),"labels.jsonl")
 if err:=os.WriteFile(path,[]byte("{\"label\":\"ham\",\"action\":\"accept\",\"cohort\":\"direct\"}\n{\"label\":\"spam\",\"action\":\"reject\",\"cohort\":\"forwarded\"}\n"),0600);err!=nil{t.Fatal(err)}
 var out,stderr bytes.Buffer
 code:=run([]string{"--require-cohorts","--min-cohort-ham=1","--min-ham=1","--min-spam=1","--max-fpr-upper=1","--min-recall-lower=0",path},&out,&stderr)
 if code!=3 {t.Fatalf("expected measured cohort failure 3, got %d: %s",code,stderr.String())}
 if !strings.Contains(out.String(),"\"cohort_gate_required\":true"){t.Fatalf("missing cohort result: %s",out.String())}
}
