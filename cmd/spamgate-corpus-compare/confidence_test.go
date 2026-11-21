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

func TestCompareWilsonBounds(t *testing.T) {
 for _, tc := range []struct { fp,n int; want float64 }{
  {0,100,0.03699349820698569},
  {100,100,1},
  {0,1,0.7934506856227627},
 } {
  got:=compareWilsonUpper(tc.fp,tc.n)
  if math.Abs(got-tc.want)>1e-10 { t.Fatalf("upper(%d,%d)=%v want %v",tc.fp,tc.n,got,tc.want) }
 }
 if !math.IsNaN(compareWilsonUpper(2,1)) { t.Fatal("invalid counts must not yield a bound") }
}

func TestCompareConfidenceAndSampleGates(t *testing.T) {
 dir:=t.TempDir()
 baseline:=filepath.Join(dir,"baseline.jsonl")
 candidate:=filepath.Join(dir,"candidate.jsonl")
 raw:="{\"id\":\"clean1\",\"truth\":\"clean\",\"score\":0.1}\n{\"id\":\"spam1\",\"truth\":\"spam\",\"score\":0.9}\n"
 for _,path:=range []string{baseline,candidate} {
  if err:=os.WriteFile(path,[]byte(raw),0600);err!=nil{t.Fatal(err)}
 }
 cases:=[]struct { name string; args []string; want int }{
  {"baseline",nil,0},
  {"insufficient clean",[]string{"-min-clean","2"},1},
  {"insufficient spam",[]string{"-min-spam","2"},1},
  {"confidence rejects zero observed fp",[]string{"-max-candidate-fpr-upper-95","0.5"},1},
  {"confidence accepts upper bound",[]string{"-max-candidate-fpr-upper-95","0.8"},0},
  {"invalid negative",[]string{"-max-candidate-fpr","-1"},2},
  {"invalid nan",[]string{"-max-candidate-fpr","NaN"},2},
  {"invalid confidence",[]string{"-max-candidate-fpr-upper-95","2"},2},
 }
 for _,tc:=range cases {t.Run(tc.name,func(t *testing.T){
  args:=append([]string{"-baseline",baseline,"-candidate",candidate},tc.args...)
  var out,errOut bytes.Buffer
  code:=compareRun(args,&out,&errOut)
  if code!=tc.want{t.Fatalf("exit %d want %d: %s",code,tc.want,errOut.String())}
  if code!=2 {
   var report comparisonReport
   if err:=json.NewDecoder(strings.NewReader(out.String())).Decode(&report);err!=nil{t.Fatal(err)}
   if report.CandidateFalsePositiveUpper95<0.79||report.CandidateFalsePositiveUpper95>0.80{t.Fatalf("bad bound: %+v",report)}
  }
 })}
}
