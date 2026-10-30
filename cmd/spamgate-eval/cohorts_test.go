package main

import (
 "bytes"
 "encoding/json"
 "os"
 "path/filepath"
 "strings"
 "testing"
)

func TestStratifiedCorpusDetectsMaskedFalsePositiveCluster(t *testing.T){
 dir:=t.TempDir()
 path:=filepath.Join(dir,"cohorts.jsonl")
 var corpus strings.Builder
 write:=func(label,action,cohort string,n int){
  for i:=0;i<n;i++{
   corpus.WriteString(`{"label":"`+label+`","action":"`+action+`","cohort":"`+cohort+`"}`+"\n")
  }
 }
 write("ham","accept","direct",10000)
 write("spam","reject","direct",10000)
 write("ham","tag","forwarded",20)
 write("ham","accept","forwarded",80)
 write("spam","reject","forwarded",100)
 if err:=os.WriteFile(path,[]byte(corpus.String()),0600);err!=nil{t.Fatal(err)}
 var out,stderr bytes.Buffer
 if code:=run([]string{path},&out,&stderr);code!=0{
  t.Fatalf("global-only gate should pass: %d %s %s",code,stderr.String(),out.String())
 }
 out.Reset();stderr.Reset()
 if code:=run([]string{"--require-cohorts",path},&out,&stderr);code!=3{
  t.Fatalf("minority cohort false positives bypassed: %d %s %s",code,stderr.String(),out.String())
 }
 var r report
 if err:=json.Unmarshal(out.Bytes(),&r);err!=nil{t.Fatal(err)}
 if r.GatePassed||r.CohortGatePassed||len(r.Cohorts)!=2||r.Cohorts[0].Name!="direct"||r.Cohorts[1].Name!="forwarded"||r.Cohorts[1].GatePassed{
  t.Fatalf("incorrect stratified result: %+v",r)
 }
}

func TestStratifiedCorpusRequiresCompletePrivacySafeLabels(t *testing.T){
 for _,bad:=range []string{
  `{"label":"ham","action":"accept","cohort":"person@example.org"}`,
  `{"label":"ham","action":"accept","cohort":"tenant-123"}`,
  `{"label":"ham","action":"accept","cohort":"../../etc/passwd"}`,
 }{
  if _,_,_,err:=readLabelledCorpus(strings.NewReader(bad+"\n"+`{"label":"spam","action":"reject"}`));err==nil{
   t.Fatalf("unsafe cohort accepted: %s",bad)
  }
 }
 c,cohorts,unspecified,err:=readLabelledCorpus(strings.NewReader(`{"label":"ham","action":"accept","cohort":"direct"}`+"\n"+`{"label":"spam","action":"reject"}`))
 if err!=nil||c.Ham!=1||unspecified!=1{t.Fatalf("legacy mix invalid: %+v %+v %d %v",c,cohorts,unspecified,err)}
 _,passed:=evaluateCohorts(cohorts,unspecified,1,1,1,0)
 if passed{t.Fatal("unlabelled mail path qualified")}
 _,passed=evaluateCohorts(map[string]counts{"direct":{Ham:1000,TN:1000,Spam:1000,TP:1000}},0,100,100,0.05,0.75)
 if passed{t.Fatal("one cohort cannot establish stratified coverage")}
}

func TestStratifiedCorpusCanPassWithTwoAdequateCohorts(t *testing.T){
 cohorts:=map[string]counts{
  "direct":{Ham:1000,TN:1000,Spam:1000,TP:1000},
  "forwarded":{Ham:1000,TN:1000,Spam:1000,TP:1000},
 }
 results,passed:=evaluateCohorts(cohorts,0,100,100,0.05,0.75)
 if !passed||len(results)!=2||!results[0].GatePassed||!results[1].GatePassed{
  t.Fatalf("valid cohorts rejected: %+v %v",results,passed)
 }
}
