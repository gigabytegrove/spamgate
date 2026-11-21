package main

import (
 "bytes"
 "os"
 "path/filepath"
 "strings"
 "testing"
)

func TestTenantPairedRegressionBudgets(t *testing.T) {
 cohorts:=map[string]tenantComparison{
  "north":{Clean:100,Spam:100,NewFalsePositives:2,FixedFalsePositives:4,NewFalseNegatives:1},
  "south":{Clean:100,Spam:100,NewFalsePositives:0,NewFalseNegatives:3,FixedFalseNegatives:5},
 }
 if !tenantGatesPassWithRegressions(cohorts,1,1,1,1,-1,-1){t.Fatal("disabled budgets should preserve previous behavior")}
 if tenantGatesPassWithRegressions(cohorts,1,1,1,1,1,-1){t.Fatal("north new false positives masked by fixes")}
 if tenantGatesPassWithRegressions(cohorts,1,1,1,1,-1,2){t.Fatal("south new false negatives masked by fixes")}
 if !tenantGatesPassWithRegressions(cohorts,1,1,1,1,2,3){t.Fatal("inclusive budgets rejected")}
 if tenantGatesPassWithRegressions(cohorts,1,1,1,1,-2,3){t.Fatal("invalid budget accepted")}
 if tenantGatesPassWithRegressions(map[string]tenantComparison{},1,1,1,1,0,0){t.Fatal("empty tenant evidence accepted")}
}

func TestTenantPairedRegressionCLI(t *testing.T) {
 dir:=t.TempDir()
 baseline:=filepath.Join(dir,"baseline.jsonl")
 candidate:=filepath.Join(dir,"candidate.jsonl")
 b:=strings.Join([]string{
  `{"id":"n1","tenant":"north","truth":"clean","score":0.1}`,
  `{"id":"n2","tenant":"north","truth":"spam","score":0.9}`,
  `{"id":"s1","tenant":"south","truth":"clean","score":0.1}`,
  `{"id":"s2","tenant":"south","truth":"spam","score":0.9}`,
 },"\n")+"\n"
 c:=strings.Replace(b,`"id":"n1","tenant":"north","truth":"clean","score":0.1`,`"id":"n1","tenant":"north","truth":"clean","score":0.9`,1)
 c=strings.Replace(c,`"id":"s2","tenant":"south","truth":"spam","score":0.9`,`"id":"s2","tenant":"south","truth":"spam","score":0.1`,1)
 if err:=os.WriteFile(baseline,[]byte(b),0600);err!=nil{t.Fatal(err)}
 if err:=os.WriteFile(candidate,[]byte(c),0600);err!=nil{t.Fatal(err)}
 common:=[]string{"-baseline",baseline,"-candidate",candidate,"-require-tenants","-max-new-fp=1","-max-new-fn=1"}
 cases:=[]struct{name string; extra []string; want int}{
  {"allowed",nil,0},
  {"false positive regression",[]string{"-max-tenant-new-fp=0"},1},
  {"false negative regression",[]string{"-max-tenant-new-fn=0"},1},
  {"inclusive tenant budget",[]string{"-max-tenant-new-fp=1","-max-tenant-new-fn=1"},0},
  {"disabled tenant mode",[]string{"-require-tenants=false","-max-tenant-new-fp=0"},2},
  {"invalid negative",[]string{"-max-tenant-new-fp=-2"},2},
 }
 for _,tc:=range cases {t.Run(tc.name,func(t *testing.T){
  var stdout,stderr bytes.Buffer
  args:=append(append([]string{},common...),tc.extra...)
  got:=compareRun(args,&stdout,&stderr)
  if got!=tc.want {t.Fatalf("code=%d want=%d output=%s stderr=%s",got,tc.want,stdout.String(),stderr.String())}
  if got==1 && !strings.Contains(stdout.String(),`"by_tenant"`) {t.Fatal("failed gate must emit diagnostic tenant evidence")}
 })}
}
