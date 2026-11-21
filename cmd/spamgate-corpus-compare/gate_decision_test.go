package main

import (
 "bytes"
 "encoding/json"
 "os"
 "path/filepath"
 "reflect"
 "strings"
 "testing"
)

func TestGateDecisionAllFailuresAndStableTenantOrdering(t *testing.T) {
 r:=comparisonReport{Clean:2,Spam:2,NewFalsePositives:1,NewFalseNegatives:1,
  CandidateFalsePositiveRate:.5,CandidateFalseNegativeRate:.5,
  CandidateFalsePositiveUpper95:.8,CandidateFalseNegativeUpper95:.8,
  ByTenant:map[string]tenantComparison{
   "z":{Clean:1,Spam:1,NewFalsePositives:1,CandidateFalsePositiveRate:1},
   "a":{Clean:1,Spam:1,NewFalseNegatives:1,CandidateFalseNegativeRate:1},
  }}
 l:=comparisonGateLimits{RequireTenants:true,MinClean:3,MinSpam:3,MaxNewFP:0,MaxNewFN:0,
  MaxFPR:.1,MaxFNR:.1,MaxFPRUpper:.2,MaxFNRUpper:.2,
  MinTenantClean:2,MinTenantSpam:2,MaxTenantNewFP:0,MaxTenantNewFN:0,
  MaxTenantFPR:.2,MaxTenantFNR:.2,MaxTenantFPRUpper:1,MaxTenantFNRUpper:1}
 first:=assessComparisonGates(r,l)
 if len(first)<12 {t.Fatalf("missing independent failures: %v",first)}
 for i:=0;i<100;i++ {if got:=assessComparisonGates(r,l);!reflect.DeepEqual(first,got){t.Fatalf("unstable order: %v vs %v",first,got)}}
 if strings.Index(strings.Join(first,"|"),"tenant[\\\"a\\\"]")>strings.Index(strings.Join(first,"|"),"tenant[\\\"z\\\"]"){t.Fatal("tenant ordering not deterministic")}
}
func TestGateDecisionExplicitPassAndFailureJSON(t *testing.T){
 dir:=t.TempDir()
 baseline:=filepath.Join(dir,"baseline.jsonl");candidate:=filepath.Join(dir,"candidate.jsonl")
 corpus:="{\\"id\\":\\"a\\",\\"truth\\":\\"clean\\",\\"tenant\\":\\"one\\",\\"score\\":0.1}\\n{\\"id\\":\\"b\\",\\"truth\\":\\"spam\\",\\"tenant\\":\\"one\\",\\"score\\":0.9}\\n"
 corpus=strings.ReplaceAll(corpus,"\\\\n","\n")
 for _,p:=range []string{baseline,candidate}{if err:=os.WriteFile(p,[]byte(corpus),0600);err!=nil{t.Fatal(err)}}
 args:=[]string{"-baseline",baseline,"-candidate",candidate,"-require-tenants"}
 var out,errs bytes.Buffer
 if code:=compareRun(args,&out,&errs);code!=0{t.Fatalf("pass code %d: %s",code,errs.String())}
 var report comparisonReport
 if err:=json.Unmarshal(out.Bytes(),&report);err!=nil{t.Fatal(err)}
 if !report.GatePassed||len(report.GateFailures)!=0{t.Fatalf("unexpected failure: %+v",report)}
 out.Reset();errs.Reset()
 args=append(args,"-min-tenant-clean","2")
 if code:=compareRun(args,&out,&errs);code!=1{t.Fatalf("failure code %d: %s",code,errs.String())}
 if err:=json.Unmarshal(out.Bytes(),&report);err!=nil{t.Fatal(err)}
 if report.GatePassed||len(report.GateFailures)==0||report.GateFailures[0]!="tenant[\\"one\\"].minimum_clean_samples"{t.Fatalf("missing machine-readable reason: %+v",report)}
}
