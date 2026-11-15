package main

import (
 "bytes"
 "encoding/json"
 "os"
 "path/filepath"
 "strings"
 "testing"
)

func TestDisruptiveDispositionGateAndCohorts(t *testing.T) {
 var corpus strings.Builder
 for _, cohort := range []string{"direct","forwarded"} {
  for i:=0;i<1000;i++ {
   action:="accept"
   if cohort=="forwarded" && i==0 {action="quarantine"}
   if cohort=="forwarded" && i==1 {action="soft_reject"}
   if cohort=="direct" && i==0 {action="tag"}
   corpus.WriteString(`{"label":"ham","action":"`+action+`","cohort":"`+cohort+`"}`+"\n")
  }
  for i:=0;i<1000;i++ {
   corpus.WriteString(`{"label":"spam","action":"reject","cohort":"`+cohort+`"}`+"\n")
  }
 }
 path:=filepath.Join(t.TempDir(),"labels.jsonl")
 if err:=os.WriteFile(path,[]byte(corpus.String()),0600);err!=nil{t.Fatal(err)}
 args:=[]string{"--require-cohorts","--max-fpr-upper=0.02","--max-cohort-fpr-upper=0.03","--max-disruptive-fpr-upper=0.01","--max-cohort-disruptive-fpr-upper=0.006",path}
 var out,errs bytes.Buffer
 if code:=run(args,&out,&errs);code!=3 {t.Fatalf("expected minority cohort failure: %d %s",code,errs.String())}
 var r report
 if err:=json.Unmarshal(out.Bytes(),&r);err!=nil{t.Fatal(err)}
 if !r.DisruptiveGatePassed||r.CohortGatePassed||r.Counts.QuarantinedHam!=1||r.Counts.SoftRejectedHam!=1||r.Counts.RejectedHam!=0||r.Counts.FP!=3 {t.Fatalf("unexpected accounting: %+v",r)}
 if len(r.Cohorts)!=2||!r.Cohorts[0].DisruptiveGatePassed||r.Cohorts[1].DisruptiveGatePassed {t.Fatalf("incorrect cohort disposition: %+v",r.Cohorts)}
 args[4]="--max-cohort-disruptive-fpr-upper=0.01"
 out.Reset();errs.Reset()
 if code:=run(args,&out,&errs);code!=0 {t.Fatalf("expected passing relaxed bound: %d %s",code,errs.String())}
}

func TestDisruptiveGateRefusesInvalidOrUnenforcedThreshold(t *testing.T) {
 for _,value:=range []string{"NaN","+Inf","-Inf","-0.01","1.01"} {
  for _,flag:=range []string{"--max-disruptive-fpr-upper=","--max-cohort-disruptive-fpr-upper="} {
   var out,errs bytes.Buffer
   if code:=run([]string{"--require-cohorts",flag+value,"missing.jsonl"},&out,&errs);code!=2 {t.Fatalf("accepted %s%s",flag,value)}
  }
 }
 var out,errs bytes.Buffer
 if code:=run([]string{"--max-cohort-disruptive-fpr-upper=0.01","missing.jsonl"},&out,&errs);code!=2 {t.Fatalf("unenforced cohort gate: %d",code)}
}
