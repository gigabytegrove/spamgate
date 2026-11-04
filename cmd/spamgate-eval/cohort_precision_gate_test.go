package main

import (
 "bytes"
 "encoding/json"
 "os"
 "path/filepath"
 "strings"
 "testing"
)

func TestCohortPrecisionGatePreventsMinorityFalsePositiveMasking(t *testing.T) {
 cohorts:=map[string]counts{
  "direct":{Ham:1000,Spam:1000,TP:990,FP:0,TN:1000,FN:10},
  "forwarded":{Ham:100,Spam:100,TP:90,FP:40,TN:60,FN:10},
 }
 baseline,ok:=evaluateCohortsWithPrecision(cohorts,0,50,50,1,0,0)
 if !ok || len(baseline)!=2 {t.Fatalf("baseline failed: %v %+v",ok,baseline)}
 result,ok:=evaluateCohortsWithPrecision(cohorts,0,50,50,1,0,0.8)
 if ok || result[0].Name!="direct" || !result[0].GatePassed || result[1].Name!="forwarded" || result[1].GatePassed {
  t.Fatalf("minority precision not enforced: %v %+v",ok,result)
 }
 if result[1].PrecisionLower95>=0.8 || result[1].MinimumPrecisionLower95!=0.8 {t.Fatalf("incorrect confidence evidence: %+v",result[1])}
}

func TestCohortPrecisionGateNoPredictions(t *testing.T) {
 groups:=map[string]counts{
  "direct":{Ham:100,Spam:100,TN:100,FN:100},
  "bulk":{Ham:100,Spam:100,TP:100,TN:100},
 }
 results,ok:=evaluateCohortsWithPrecision(groups,0,1,1,1,0,0.01)
 if ok {t.Fatalf("empty predicted positives accepted: %+v",results)}
 for _,r:=range results {
  if r.Name=="direct" && (r.GatePassed || r.PrecisionLower95!=0) {t.Fatalf("invalid zero prediction result: %+v",r)}
 }
}

func TestCohortPrecisionCLI(t *testing.T) {
 dir:=t.TempDir()
 path:=filepath.Join(dir,"labels.jsonl")
 var corpus strings.Builder
 for _,cohort:=range []string{"direct","forwarded"} {
  for i:=0;i<100;i++ {
   action:="accept"
   if cohort=="forwarded" && i<40 {action="tag"}
   corpus.WriteString("{\"label\":\"ham\",\"action\":\""+action+"\",\"cohort\":\""+cohort+"\"}\n")
  }
  for i:=0;i<100;i++ {
   corpus.WriteString("{\"label\":\"spam\",\"action\":\"reject\",\"cohort\":\""+cohort+"\"}\n")
  }
 }
 if err:=os.WriteFile(path,[]byte(corpus.String()),0600);err!=nil{t.Fatal(err)}
 args:=[]string{"--require-cohorts","--min-ham=1","--min-spam=1","--max-fpr-upper=1","--min-recall-lower=0","--min-cohort-ham=1","--min-cohort-spam=1","--max-cohort-fpr-upper=1","--min-cohort-recall-lower=0","--min-cohort-precision-lower=0.8",path}
 var out,errout bytes.Buffer
 if code:=run(args,&out,&errout);code!=3{t.Fatalf("expected gate failure, got %d: %s",code,errout.String())}
 var report struct {Cohorts []cohortResult `json:"cohorts"`; CohortGatePassed bool `json:"cohort_gate_passed"`}
 if err:=json.Unmarshal(out.Bytes(),&report);err!=nil{t.Fatal(err)}
 if report.CohortGatePassed || len(report.Cohorts)!=2 || report.Cohorts[1].GatePassed || report.Cohorts[1].MinimumPrecisionLower95!=0.8 {t.Fatalf("bad JSON: %+v",report)}
 for _,bad:=range []string{"NaN","-0.01","1.01"} {
  out.Reset();errout.Reset()
  if code:=run([]string{"--min-cohort-precision-lower="+bad,path},&out,&errout);code!=2{t.Fatalf("accepted %q: %d",bad,code)}
 }
}
