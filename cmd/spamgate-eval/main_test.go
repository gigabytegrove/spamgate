package main

import (
 "bytes"
 "encoding/json"
 "math"
 "os"
 "path/filepath"
 "strings"
 "testing"
)
func TestLabelledCorpusConfusionMatrixAndNoPII(t *testing.T){
 corpus:=strings.Join([]string{
  `{"label":"ham","action":"accept"}`,
  `{"label":"ham","action":"tag"}`,
  `{"label":"ham","action":"soft_reject"}`,
  `{"label":"spam","action":"reject"}`,
  `{"label":"spam","action":"quarantine"}`,
  `{"label":"spam","action":"accept"}`,
 },"\n")
 c,err:=readLabels(strings.NewReader(corpus));if err!=nil{t.Fatal(err)}
 if c.Ham!=3||c.Spam!=3||c.TP!=2||c.FP!=2||c.TN!=1||c.FN!=1{t.Fatalf("incorrect counts: %+v",c)}
 r:=evaluate(c,1000,1000,0.01,0.90)
 if math.Abs(r.FalsePositiveRate-2.0/3)>1e-8||math.Abs(r.Recall-2.0/3)>1e-8||math.Abs(r.Precision-0.5)>1e-8{t.Fatalf("incorrect rates: %+v",r)}
 if r.GatePassed{t.Fatal("weak sample falsely qualified")}
 if wilson(0,1000,true)<=0||wilson(1000,1000,false)>=1{t.Fatal("confidence interval ignored finite sample size")}
}
func TestLabelReaderRejectsMisleadingAndUnboundedInput(t *testing.T){
 for _,bad:=range []string{
  `{"label":"ham","action":"accept","subject":"secret"}`,
  `{"label":"spam","action":"unknown"}`,
  `{"label":"unknown","action":"tag"}`,
  `{"label":"ham","action":"accept"} {"label":"spam","action":"reject"}`,
  `{"label":"ham","action":"accept"}`,
  strings.Repeat("x",70<<10),
 }{
  if _,err:=readLabels(strings.NewReader(bad));err==nil{t.Fatalf("invalid corpus accepted: %q",bad[:min(len(bad),60)])}
 }
}
func TestEvaluationCLIThresholdsAndExitCodes(t *testing.T){
 dir:=t.TempDir()
 path:=filepath.Join(dir,"labels.jsonl")
 data:=strings.Repeat(`{"label":"ham","action":"accept"}`+"\n",1000)+strings.Repeat(`{"label":"spam","action":"reject"}`+"\n",1000)
 if err:=os.WriteFile(path,[]byte(data),0600);err!=nil{t.Fatal(err)}
 var out,errout bytes.Buffer
 code:=run([]string{path},&out,&errout)
 if code!=0{t.Fatalf("perfect corpus failed: code=%d err=%s output=%s",code,errout.String(),out.String())}
 var r report
 if err:=json.Unmarshal(out.Bytes(),&r);err!=nil{t.Fatal(err)}
 if !r.GatePassed||r.FalsePositiveUpper95<=0||r.RecallLower95>=1{t.Fatalf("false confidence: %+v",r)}
 out.Reset();errout.Reset()
 if code:=run([]string{"--min-ham=2000",path},&out,&errout);code!=3{t.Fatalf("underpowered corpus accepted: %d",code)}
 out.Reset();errout.Reset()
 if code:=run([]string{"--max-fpr-upper=0.001",path},&out,&errout);code!=3{t.Fatalf("overconfident false-positive gate accepted: %d",code)}
 out.Reset();errout.Reset()
 if code:=run([]string{"--max-fpr-upper=NaN",path},&out,&errout);code!=2{t.Fatalf("NaN threshold accepted: %d",code)}
}
