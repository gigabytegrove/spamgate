package main

import (
 "bytes"
 "os"
 "path/filepath"
 "strings"
 "testing"
)

func TestCombinedGlobalAndCohortBudgetRejectsImpossibleConfigurations(t *testing.T) {
 tests:=[]struct{name string;args []string}{
  {"ham dominated by global",[]string{"--require-cohorts","--max-records=10","--min-ham=8","--min-spam=1","--min-cohort-ham=1","--min-cohort-spam=2"}},
  {"spam dominated by global",[]string{"--require-cohorts","--max-records=10","--min-ham=1","--min-spam=8","--min-cohort-ham=2","--min-cohort-spam=1"}},
  {"both global and cohorts",[]string{"--require-cohorts","--max-records=10","--min-ham=6","--min-spam=6","--min-cohort-ham=2","--min-cohort-spam=2"}},
  {"overflow safe",[]string{"--require-cohorts","--max-records=9223372036854775807","--min-ham=9223372036854775800","--min-spam=1","--min-cohort-ham=1","--min-cohort-spam=10"}},
 }
 for _,tc:=range tests {t.Run(tc.name,func(t *testing.T){
  args:=append(append([]string{},tc.args...),"this-corpus-must-not-be-opened.jsonl")
  var stdout,stderr bytes.Buffer
  if got:=run(args,&stdout,&stderr);got!=2 {t.Fatalf("exit=%d stderr=%q",got,stderr.String())}
  if stdout.Len()!=0 {t.Fatalf("unexpected report: %s",stdout.String())}
  if !strings.Contains(stderr.String(),"--max-records") {t.Fatalf("expected budget diagnostic, got %q",stderr.String())}
  if strings.Contains(stderr.String(),"cannot open corpus") {t.Fatal("opened corpus before rejecting impossible budget")}
 })}
}

func TestCombinedGlobalAndCohortBudgetExactFit(t *testing.T) {
 dir:=t.TempDir()
 path:=filepath.Join(dir,"labels.jsonl")
 corpus:=strings.Join([]string{
  `{"label":"ham","action":"accept","cohort":"direct"}`,
  `{"label":"spam","action":"reject","cohort":"direct"}`,
  `{"label":"ham","action":"accept","cohort":"forwarded"}`,
  `{"label":"spam","action":"reject","cohort":"forwarded"}`,
 },"\n")+"\n"
 if err:=os.WriteFile(path,[]byte(corpus),0600);err!=nil{t.Fatal(err)}
 var out,errOut bytes.Buffer
 rc:=run([]string{"--require-cohorts","--max-records=4","--min-ham=2","--min-spam=2","--min-cohort-ham=1","--min-cohort-spam=1","--max-fpr-upper=1","--min-recall-lower=0","--max-cohort-fpr-upper=1","--min-cohort-recall-lower=0",path},&out,&errOut)
 if rc!=0 {t.Fatalf("exact-fit configuration exit=%d stderr=%s output=%s",rc,errOut.String(),out.String())}
 if !strings.Contains(out.String(),`"gate_passed":true`) {t.Fatalf("missing passing report: %s",out.String())}
}

func TestCombinedBudgetDoesNotAffectReportOnlyCohorts(t *testing.T) {
 var out,errOut bytes.Buffer
 rc:=run([]string{"--max-records=10","--min-ham=8","--min-spam=1","this-corpus-must-not-be-opened.jsonl"},&out,&errOut)
 if rc!=2 || !strings.Contains(errOut.String(),"cannot open corpus") {
  t.Fatalf("report-only configuration should pass feasibility validation, rc=%d err=%s",rc,errOut.String())
 }
}
