package main

import (
 "bytes"
 "encoding/json"
 "os"
 "path/filepath"
 "strings"
 "testing"
)

// A cohort-specific acceptance threshold must never be silently ignored.
// A configuration error is distinct from a measured failure (exit 3).
func TestCohortPrecisionThresholdRequiresEnforcement(t *testing.T) {
 path:=filepath.Join(t.TempDir(),"labels.jsonl")
 corpus:="{\"label\":\"ham\",\"action\":\"accept\",\"cohort\":\"direct\"}\n"+
  "{\"label\":\"spam\",\"action\":\"reject\",\"cohort\":\"forwarded\"}\n"
 if err:=os.WriteFile(path,[]byte(corpus),0600);err!=nil{t.Fatal(err)}
 for _,value:=range []string{"0.01","0.8","1"} {
  var out,stderr bytes.Buffer
  code:=run([]string{"--min-cohort-precision-lower="+value,"--min-ham=1","--min-spam=1",path},&out,&stderr)
  if code!=2 {t.Fatalf("threshold %s: expected configuration error 2, got %d: %s",value,code,stderr.String())}
  if out.Len()!=0 {t.Fatalf("threshold %s: emitted misleading evaluation: %s",value,out.String())}
  if !strings.Contains(stderr.String(),"--require-cohorts") {t.Fatalf("threshold %s: missing actionable error: %s",value,stderr.String())}
 }
}

func TestCohortPrecisionDisabledRemainsCompatible(t *testing.T) {
 path:=filepath.Join(t.TempDir(),"labels.jsonl")
 corpus:="{\"label\":\"ham\",\"action\":\"accept\"}\n{\"label\":\"spam\",\"action\":\"reject\"}\n"
 if err:=os.WriteFile(path,[]byte(corpus),0600);err!=nil{t.Fatal(err)}
 var out,stderr bytes.Buffer
 code:=run([]string{"--min-cohort-precision-lower=0","--min-ham=1","--min-spam=1","--max-fpr-upper=1","--min-recall-lower=0",path},&out,&stderr)
 if code!=0 {t.Fatalf("disabled cohort gate changed behavior: %d %s",code,stderr.String())}
 var result report
 if err:=json.Unmarshal(out.Bytes(),&result);err!=nil{t.Fatal(err)}
 if !result.GatePassed || result.CohortGateRequired {t.Fatalf("unexpected cohort enforcement: %+v",result)}
}
