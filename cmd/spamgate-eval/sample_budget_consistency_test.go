package main

import (
 "bytes"
 "os"
 "path/filepath"
 "strings"
 "testing"
)

// Impossible acceptance configurations must fail before touching the corpus.
// This is important when an evaluation runs in CI with a missing or private corpus.
func TestImpossibleSampleBudgetsRejectedBeforeCorpusOpen(t *testing.T) {
 cases:=[]struct{name string; args []string}{
  {"ham above record cap",[]string{"--min-ham=3","--min-spam=1","--max-records=2"}},
  {"spam above record cap",[]string{"--min-ham=1","--min-spam=3","--max-records=2"}},
  {"combined minimum above record cap",[]string{"--min-ham=2","--min-spam=2","--max-records=3"}},
  {"combined minimum overflows int boundary",[]string{"--min-ham=2147483647","--min-spam=2147483647","--max-records=2147483647"}},
 }
 for _,tc:=range cases {
  t.Run(tc.name,func(t *testing.T){
   args:=append(append([]string{},tc.args...),filepath.Join(t.TempDir(),"missing.jsonl"))
   var out,stderr bytes.Buffer
   if code:=run(args,&out,&stderr);code!=2 {t.Fatalf("exit=%d stderr=%q",code,stderr.String())}
   if out.Len()!=0 {t.Fatalf("invalid configuration produced report: %s",out.String())}
   if strings.Contains(stderr.String(),"cannot open corpus") {t.Fatalf("opened corpus before validating record budget: %s",stderr.String())}
  })
 }
}

func TestFeasibleSampleBudgetReachesCorpusEvaluation(t *testing.T) {
 dir:=t.TempDir()
 corpus:=filepath.Join(dir,"labels.jsonl")
 data:="{\"label\":\"ham\",\"action\":\"accept\"}\n{\"label\":\"spam\",\"action\":\"reject\"}\n"
 if err:=os.WriteFile(corpus,[]byte(data),0600);err!=nil {t.Fatal(err)}
 var out,stderr bytes.Buffer
 code:=run([]string{"--min-ham=1","--min-spam=1","--max-records=2","--max-fpr-upper=1","--min-recall-lower=0",corpus},&out,&stderr)
 if code!=0 {t.Fatalf("feasible budget rejected: exit=%d stderr=%s report=%s",code,stderr.String(),out.String())}
 if !strings.Contains(out.String(),"\"gate_passed\":true"){t.Fatalf("missing successful evaluation: %s",out.String())}
}
