package main

import (
 "bytes"
 "encoding/json"
 "os"
 "path/filepath"
 "strings"
 "testing"
)

func TestCohortRejectGateCatchesMinorityMailPath(t *testing.T) {
 dir:=t.TempDir()
 path:=filepath.Join(dir,"labels.jsonl")
 var corpus strings.Builder
 for _,cohort:=range []string{"direct","forwarded"} {
  for i:=0;i<1000;i++ {
   action:="accept"
   if cohort=="forwarded" && i==0 {action="reject"}
   corpus.WriteString(`{"label":"ham","action":"`+action+`","cohort":"`+cohort+`"}`+"\n")
  }
  for i:=0;i<1000;i++ {
   corpus.WriteString(`{"label":"spam","action":"reject","cohort":"`+cohort+`"}`+"\n")
  }
 }
 if err:=os.WriteFile(path,[]byte(corpus.String()),0600);err!=nil{t.Fatal(err)}
 args:=[]string{"--require-cohorts","--max-fpr-upper=0.02","--max-cohort-fpr-upper=0.03","--max-cohort-reject-fpr-upper=0.005",path}
 var out,errs bytes.Buffer
 if code:=run(args,&out,&errs);code!=3{t.Fatalf("expected cohort rejection failure, code=%d stderr=%s",code,errs.String())}
 var r report
 if err:=json.Unmarshal(out.Bytes(),&r);err!=nil{t.Fatal(err)}
 if !r.RejectGatePassed || r.CohortGatePassed || r.GatePassed || len(r.Cohorts)!=2 {
  t.Fatalf("global rejection should pass but minority cohort must fail: %+v",r)
 }
 if r.Cohorts[0].Name!="direct"||!r.Cohorts[0].RejectGatePassed||r.Cohorts[1].Name!="forwarded"||r.Cohorts[1].RejectGatePassed {
  t.Fatalf("incorrect per-cohort rejection safety: %+v",r.Cohorts)
 }
 out.Reset();errs.Reset()
 args[3]="--max-cohort-reject-fpr-upper=0.01"
 if code:=run(args,&out,&errs);code!=0{t.Fatalf("expected relaxed cohort rejection threshold to pass, code=%d stderr=%s",code,errs.String())}
}

func TestCohortRejectGateRejectsInvalidAndUnenforcedThresholds(t *testing.T) {
 for _,v:=range []string{"NaN","+Inf","-Inf","-0.01","1.01"} {
  var out,errs bytes.Buffer
  if code:=run([]string{"--require-cohorts","--max-cohort-reject-fpr-upper="+v,"missing.jsonl"},&out,&errs);code!=2{
   t.Fatalf("invalid cohort threshold %q accepted: %d",v,code)
  }
 }
 var out,errs bytes.Buffer
 if code:=run([]string{"--max-cohort-reject-fpr-upper=0.01","missing.jsonl"},&out,&errs);code!=2 {
  t.Fatalf("unenforced cohort threshold accepted: %d",code)
 }
}
