package main

import (
 "bytes"
 "os"
 "path/filepath"
 "strings"
 "testing"
)

func TestImpossibleTwoCohortBudgetsFailBeforeCorpusOpen(t *testing.T) {
 cases:=[]struct{name string; flags []string}{
  {"ham alone",[]string{"--min-cohort-ham=3","--min-cohort-spam=1","--max-records=5"}},
  {"spam alone",[]string{"--min-cohort-ham=1","--min-cohort-spam=3","--max-records=5"}},
  {"combined minimum",[]string{"--min-cohort-ham=2","--min-cohort-spam=2","--max-records=7"}},
  {"max integer overflow",[]string{"--min-cohort-ham=2147483647","--min-cohort-spam=2147483647","--max-records=2147483647"}},
 }
 for _,tc:=range cases {t.Run(tc.name,func(t *testing.T){
  args:=append([]string{"--require-cohorts","--min-ham=1","--min-spam=1"},tc.flags...)
  args=append(args,filepath.Join(t.TempDir(),"nonexistent.jsonl"))
  var out,errs bytes.Buffer
  if code:=run(args,&out,&errs);code!=2 {t.Fatalf("exit=%d stderr=%s",code,errs.String())}
  if out.Len()!=0 {t.Fatalf("invalid configuration emitted JSON: %s",out.String())}
  if !strings.Contains(errs.String(),"two disjoint cohorts") {t.Fatalf("unexpected error: %s",errs.String())}
  if strings.Contains(errs.String(),"cannot open corpus") {t.Fatal("corpus opened before validation")}
 })}
}

func TestExactFitTwoCohortBudgetCanQualify(t *testing.T) {
 path:=filepath.Join(t.TempDir(),"labels.jsonl")
 data:=""
 for _,cohort:=range []string{"direct","forwarded"} {
  for _,label:=range []string{"ham","spam"} {
   action:="accept"
   if label=="spam" {action="reject"}
   data+="{\"label\":\""+label+"\",\"action\":\""+action+"\",\"cohort\":\""+cohort+"\"}\n"
  }
 }
 if err:=os.WriteFile(path,[]byte(data),0600);err!=nil {t.Fatal(err)}
 var out,errs bytes.Buffer
 code:=run([]string{"--require-cohorts","--min-ham=1","--min-spam=1","--min-cohort-ham=1","--min-cohort-spam=1","--max-records=4","--max-fpr-upper=1","--min-recall-lower=0","--max-cohort-fpr-upper=1","--min-cohort-recall-lower=0",path},&out,&errs)
 if code!=0 {t.Fatalf("exact fit rejected: code=%d stderr=%s report=%s",code,errs.String(),out.String())}
 if !strings.Contains(out.String(),"\"cohort_gate_passed\":true") {t.Fatalf("missing cohort pass: %s",out.String())}
}

func TestReportOnlyCohortDefaultsDoNotConsumeRecordBudget(t *testing.T) {
 path:=filepath.Join(t.TempDir(),"labels.jsonl")
 data:="{\"label\":\"ham\",\"action\":\"accept\"}\n{\"label\":\"spam\",\"action\":\"reject\"}\n"
 if err:=os.WriteFile(path,[]byte(data),0600);err!=nil {t.Fatal(err)}
 var out,errs bytes.Buffer
 code:=run([]string{"--min-ham=1","--min-spam=1","--max-records=2","--max-fpr-upper=1","--min-recall-lower=0",path},&out,&errs)
 if code!=0 {t.Fatalf("report-only mode rejected: code=%d stderr=%s",code,errs.String())}
}
