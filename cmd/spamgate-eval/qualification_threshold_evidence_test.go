package main

import (
 "bytes"
 "encoding/json"
 "os"
 "path/filepath"
 "strings"
 "testing"
)

func TestEvaluationReportIncludesEveryConfiguredSafetyGate(t *testing.T) {
 path:=filepath.Join(t.TempDir(),"labels.jsonl")
 data:=[]byte("{\"label\":\"ham\",\"action\":\"accept\",\"cohort\":\"direct\"}\n{\"label\":\"spam\",\"action\":\"reject\",\"cohort\":\"direct\"}\n")
 if err:=os.WriteFile(path,data,0600);err!=nil {t.Fatal(err)}
 args:=[]string{
  "--min-ham=1","--min-spam=1",
  "--max-fpr-upper=0.25","--min-recall-lower=0.1",
  "--min-precision-lower=0.2","--max-reject-fpr-upper=0.3",
  "--max-disruptive-fpr-upper=0.4",
  "--min-cohort-ham=2","--min-cohort-spam=3",
  "--max-cohort-fpr-upper=0.35","--min-cohort-recall-lower=0.15",
  "--min-cohort-precision-lower=0.25",
  "--max-cohort-reject-fpr-upper=0.45",
  "--max-cohort-disruptive-fpr-upper=0.55",
  "--require-cohorts",path,
 }
 var out,errs bytes.Buffer
 code:=run(args,&out,&errs)
 // The intentionally undersized cohort must fail the acceptance gate, but
 // still produce an inspectable report containing the configured thresholds.
 if code!=3 {t.Fatalf("expected gate failure 3, got %d: %s",code,errs.String())}
 var result report
 if err:=json.Unmarshal(out.Bytes(),&result);err!=nil {t.Fatal(err)}
 x:=result.Qualification.Thresholds
 if x==nil {t.Fatal("acceptance thresholds missing from qualification evidence")}
 if x.MinimumHam!=1||x.MinimumSpam!=1||x.MaximumFalsePositiveUpper95!=0.25||
  x.MinimumRecallLower95!=0.1||x.MinimumPrecisionLower95!=0.2||
  x.MaximumRejectFalsePositiveUpper95!=0.3||x.MaximumDisruptiveFalsePositiveUpper95!=0.4||
  x.MinimumCohortHam!=2||x.MinimumCohortSpam!=3||
  x.MaximumCohortFalsePositiveUpper95!=0.35||x.MinimumCohortRecallLower95!=0.15||
  x.MinimumCohortPrecisionLower95!=0.25||
  x.MaximumCohortRejectFalsePositiveUpper95!=0.45||
  x.MaximumCohortDisruptiveFalsePositiveUpper95!=0.55 {
  t.Fatalf("reported thresholds differ from configured policy: %+v",x)
 }
 if strings.Contains(out.String(),path)||strings.Contains(out.String(),"labels.jsonl") {
  t.Fatal("qualification evidence leaked local corpus path")
 }
}

func TestEvaluationReportIncludesDefaultThresholds(t *testing.T) {
 path:=filepath.Join(t.TempDir(),"labels.jsonl")
 if err:=os.WriteFile(path,[]byte("{\"label\":\"ham\",\"action\":\"accept\"}\n{\"label\":\"spam\",\"action\":\"reject\"}\n"),0600);err!=nil {t.Fatal(err)}
 var out,errs bytes.Buffer
 code:=run([]string{"--min-ham=1","--min-spam=1",path},&out,&errs)
 if code!=3 {t.Fatalf("expected statistically insufficient corpus, got %d: %s",code,errs.String())}
 var result report
 if err:=json.Unmarshal(out.Bytes(),&result);err!=nil {t.Fatal(err)}
 x:=result.Qualification.Thresholds
 if x==nil||x.MaximumRejectFalsePositiveUpper95!=1||x.MaximumDisruptiveFalsePositiveUpper95!=1||
  x.MaximumCohortRejectFalsePositiveUpper95!=1||x.MaximumCohortDisruptiveFalsePositiveUpper95!=1 {
  t.Fatalf("disabled-by-default safety gates not disclosed: %+v",x)
 }
}
