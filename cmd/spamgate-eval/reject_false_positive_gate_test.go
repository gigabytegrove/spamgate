package main

import (
 "bytes"
 "encoding/json"
 "os"
 "path/filepath"
 "strings"
 "testing"
)

func TestRejectSpecificFalsePositiveGate(t *testing.T) {
 dir:=t.TempDir()
 path:=filepath.Join(dir,"corpus.jsonl")
 corpus:=strings.Repeat("{\"label\":\"ham\",\"action\":\"accept\"}\n",999)+
  "{\"label\":\"ham\",\"action\":\"reject\"}\n"+
  strings.Repeat("{\"label\":\"spam\",\"action\":\"reject\"}\n",1000)
 if err:=os.WriteFile(path,[]byte(corpus),0600);err!=nil{t.Fatal(err)}
 var out,errOut bytes.Buffer
 args:=[]string{"--max-fpr-upper=0.02","--max-reject-fpr-upper=0.001",path}
 if code:=run(args,&out,&errOut);code!=3{t.Fatalf("expected reject-specific gate failure, code=%d err=%s",code,errOut.String())}
 var r report
 if err:=json.Unmarshal(out.Bytes(),&r);err!=nil{t.Fatal(err)}
 if r.Counts.RejectedHam!=1||r.Counts.RejectedSpam!=1000||r.RejectGatePassed||r.GatePassed {
  t.Fatalf("incorrect rejection safety accounting: %+v",r)
 }
 if r.RejectFalsePositiveUpper95<=0.001{t.Fatalf("unsafe confidence upper bound: %+v",r)}
 out.Reset();errOut.Reset()
 if code:=run([]string{"--max-fpr-upper=0.02","--max-reject-fpr-upper=0.01",path},&out,&errOut);code!=0{
  t.Fatalf("expected permissive rejection gate to pass, code=%d err=%s",code,errOut.String())
 }
}

func TestRejectGateRejectsNonFiniteAndOutOfRangeThresholds(t *testing.T) {
 for _,v:=range []string{"NaN","+Inf","-Inf","-0.1","1.01"}{
  var out,errOut bytes.Buffer
  if code:=run([]string{"--max-reject-fpr-upper="+v,"unused.jsonl"},&out,&errOut);code!=2{
   t.Fatalf("invalid threshold %q accepted with code %d",v,code)
  }
 }
}

func TestRejectCountsIncludeCohortButDoNotDoubleCount(t *testing.T) {
 data:=strings.Join([]string{
  `{"label":"ham","action":"reject","cohort":"direct"}`,
  `{"label":"ham","action":"quarantine","cohort":"direct"}`,
  `{"label":"spam","action":"reject","cohort":"forwarded"}`,
  `{"label":"spam","action":"tag","cohort":"forwarded"}`,
 },"\n")
 c,cohorts,_,err:=readLabelledCorpus(strings.NewReader(data))
 if err!=nil{t.Fatal(err)}
 if c.RejectedHam!=1||c.RejectedSpam!=1||cohorts["direct"].RejectedHam!=1||cohorts["forwarded"].RejectedSpam!=1{
  t.Fatalf("incorrect reject counts global=%+v cohorts=%+v",c,cohorts)
 }
 if c.FP!=2||c.TP!=2{t.Fatalf("existing intervention accounting regressed: %+v",c)}
}
