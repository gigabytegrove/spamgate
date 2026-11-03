package main

import (
 "bytes"
 "encoding/json"
 "os"
 "path/filepath"
 "strings"
 "testing"
)

func TestPrecisionConfidenceGate(t *testing.T) {
 c:=counts{Ham:100,Spam:100,TP:80,FP:20,TN:80,FN:20}
 base:=evaluateWithPrecision(c,1,1,1,0,0)
 if !base.GatePassed {t.Fatal("legacy gate unexpectedly failed")}
 strict:=evaluateWithPrecision(c,1,1,1,0,0.75)
 if strict.GatePassed {t.Fatalf("precision Wilson lower bound should fail: %+v",strict)}
 if strict.Precision!=0.8 || strict.PrecisionLower95>=0.75 || strict.PrecisionLower95<=0 {
  t.Fatalf("unexpected precision confidence: %+v",strict)
 }
 permissive:=evaluateWithPrecision(c,1,1,1,0,0.70)
 if !permissive.GatePassed {t.Fatalf("confidence gate should pass: %+v",permissive)}
}

func TestPrecisionGateRejectsNoPositivePredictions(t *testing.T) {
 c:=counts{Ham:10,Spam:10,TN:10,FN:10}
 r:=evaluateWithPrecision(c,1,1,1,0,0.01)
 if r.GatePassed || r.PrecisionLower95!=0 {t.Fatalf("zero positive predictions passed: %+v",r)}
}

func TestPrecisionGateCLIAndJSON(t *testing.T) {
 dir:=t.TempDir()
 corpus:=filepath.Join(dir,"labels.jsonl")
 data:=strings.Repeat("{\"label\":\"ham\",\"action\":\"accept\"}\n",20)+strings.Repeat("{\"label\":\"spam\",\"action\":\"reject\"}\n",20)
 if err:=os.WriteFile(corpus,[]byte(data),0600);err!=nil{t.Fatal(err)}
 var out,stderr bytes.Buffer
 args:=[]string{"--min-ham=1","--min-spam=1","--max-fpr-upper=1","--min-recall-lower=0","--min-precision-lower=0.99",corpus}
 if code:=run(args,&out,&stderr);code!=3{t.Fatalf("expected confidence gate exit 3, got %d: %s",code,stderr.String())}
 var result report
 if err:=json.Unmarshal(out.Bytes(),&result);err!=nil{t.Fatal(err)}
 if result.GatePassed || result.MinimumPrecisionLower95!=0.99 || result.PrecisionLower95>=0.99 {t.Fatalf("bad JSON gate: %+v",result)}
 for _,invalid:=range []string{"NaN","-0.1","1.1"}{
  out.Reset();stderr.Reset()
  if code:=run([]string{"--min-precision-lower="+invalid,corpus},&out,&stderr);code!=2{
   t.Fatalf("invalid precision %q accepted with exit %d",invalid,code)
  }
 }
}
