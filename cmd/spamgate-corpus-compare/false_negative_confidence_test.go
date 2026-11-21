package main

import (
 "bytes"
 "encoding/json"
 "math"
 "os"
 "path/filepath"
 "testing"
)

func TestPairedFalseNegativeConfidenceAndAcceptance(t *testing.T) {
 dir:=t.TempDir()
 base:=filepath.Join(dir,"base.jsonl")
 candidate:=filepath.Join(dir,"candidate.jsonl")
 baseline:="{\"id\":\"clean1\",\"truth\":\"clean\",\"score\":0.1}\n{\"id\":\"spam1\",\"truth\":\"spam\",\"score\":0.9}\n{\"id\":\"spam2\",\"truth\":\"spam\",\"score\":0.9}\n"
 changed:="{\"id\":\"clean1\",\"truth\":\"clean\",\"score\":0.1}\n{\"id\":\"spam1\",\"truth\":\"spam\",\"score\":0.1}\n{\"id\":\"spam2\",\"truth\":\"spam\",\"score\":0.9}\n"
 if err:=os.WriteFile(base,[]byte(baseline),0600);err!=nil{t.Fatal(err)}
 if err:=os.WriteFile(candidate,[]byte(changed),0600);err!=nil{t.Fatal(err)}
 cases:=[]struct{name string; extra []string; code int}{
  {"default new false negative",nil,1},
  {"allowed regression",[]string{"-max-new-fn","1"},0},
  {"rate gate",[]string{"-max-new-fn","1","-max-candidate-fnr","0.49"},1},
  {"rate accepted",[]string{"-max-new-fn","1","-max-candidate-fnr","0.5"},0},
  {"confidence rejects",[]string{"-max-new-fn","1","-max-candidate-fnr-upper-95","0.8"},1},
  {"confidence accepts",[]string{"-max-new-fn","1","-max-candidate-fnr-upper-95","1"},0},
  {"invalid rate",[]string{"-max-candidate-fnr","-0.1"},2},
  {"invalid bound",[]string{"-max-candidate-fnr-upper-95","NaN"},2},
 }
 for _,tc:=range cases{t.Run(tc.name,func(t *testing.T){
  args:=append([]string{"-baseline",base,"-candidate",candidate},tc.extra...)
  var out,stderr bytes.Buffer
  code:=compareRun(args,&out,&stderr)
  if code!=tc.code{t.Fatalf("exit %d want %d: %s",code,tc.code,stderr.String())}
  if code==2{return}
  var report comparisonReport
  if err:=json.Unmarshal(out.Bytes(),&report);err!=nil{t.Fatal(err)}
  if report.CandidateFalseNegatives!=1||report.Spam!=2||report.NewFalseNegatives!=1{t.Fatalf("bad counts: %+v",report)}
  if math.Abs(report.CandidateFalseNegativeRate-0.5)>1e-12{t.Fatalf("bad false negative rate: %+v",report)}
  if report.CandidateFalseNegativeUpper95<=0.8||report.CandidateFalseNegativeUpper95>1{t.Fatalf("bad Wilson bound: %+v",report)}
  if report.BaselineFalseNegativeRate!=0||report.BaselineFalseNegativeUpper95<=0{t.Fatalf("bad baseline confidence: %+v",report)}
 })}
}
