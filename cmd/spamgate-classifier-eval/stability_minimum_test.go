package main

import (
 "bytes"
 "encoding/json"
 "strings"
 "testing"
)

// The beta corpus has three alpha samples and two beta samples.
// A floor of three must fail beta even when the flip-fraction gate passes.
func TestStabilityMinimumPerTenant(t *testing.T) {
 for _,tc:=range []struct{name string;args []string;fail bool}{
  {"floor passes",[]string{"-stability-margin=0.5","-max-stability-flips=1","-min-stability-samples=2"},false},
  {"beta underrepresented",[]string{"-stability-margin=0.5","-max-stability-flips=1","-min-stability-samples=3"},true},
  {"zero floor rejected",[]string{"-stability-margin=0.5","-max-stability-flips=1","-min-stability-samples=0"},true},
  {"negative floor rejected",[]string{"-stability-margin=0.5","-max-stability-flips=1","-min-stability-samples=-1"},true},
  {"floor without gate rejected",[]string{"-stability-margin=0.5","-min-stability-samples=2"},true},
 } {
  t.Run(tc.name,func(t *testing.T){
   var out bytes.Buffer
   err:=run(tc.args,strings.NewReader(stabilityCorpus),&out)
   if (err!=nil)!=tc.fail {t.Fatalf("error=%v, want failure=%v",err,tc.fail)}
   if strings.Contains(tc.name,"rejected") {
    if out.Len()!=0 {t.Fatalf("invalid options emitted report: %s",out.String())}
    return
   }
   var result struct{StabilityAudit struct{Passed bool `json:"passed"`;Tenants []struct{Tenant string `json:"tenant"`;Total int `json:"total"`;Passed bool `json:"passed"`} `json:"tenants"`} `json:"stability_audit"`}
   if e:=json.Unmarshal(out.Bytes(),&result);e!=nil {t.Fatalf("invalid report: %v: %s",e,out.String())}
   if tc.fail {
    if result.StabilityAudit.Passed || len(result.StabilityAudit.Tenants)!=2 || result.StabilityAudit.Tenants[1].Tenant!="beta" || result.StabilityAudit.Tenants[1].Passed {t.Fatalf("beta floor not enforced: %+v",result)}
   } else if !result.StabilityAudit.Passed {t.Fatalf("expected passing report: %+v",result)}
  })
 }
}
