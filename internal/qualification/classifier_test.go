package qualification

import (
 "math"
 "testing"
)
func TestEvaluateTenantIsolationAndBoundary(t *testing.T){
 samples:=[]Sample{
  {ID:"1",Tenant:"a",Spam:true,Score:.9},
  {ID:"2",Tenant:"a",Spam:false,Score:.5},
  {ID:"3",Tenant:"b",Spam:true,Score:.49},
  {ID:"4",Tenant:"b",Spam:false,Score:.1},
 }
 r,err:=Evaluate(samples,.5);if err!=nil{t.Fatal(err)}
 if r.Overall.Counts!=(Counts{TruePositive:1,FalsePositive:1,FalseNegative:1,TrueNegative:1}) {t.Fatalf("counts: %+v",r.Overall)}
 if r.Overall.Precision!=.5||r.Overall.Recall!=.5||r.Overall.FalsePositiveRate!=.5 {t.Fatalf("rates: %+v",r.Overall)}
 if r.ByTenant["a"].FalsePositive!=1||r.ByTenant["b"].FalsePositive!=0 {t.Fatalf("tenant isolation: %+v",r.ByTenant)}
}
func TestInvalidCorpus(t *testing.T){
 cases:=[]struct{name string;samples []Sample;threshold float64}{
  {"empty",nil,.5},
  {"duplicate",[]Sample{{ID:"x",Tenant:"a"},{ID:"x",Tenant:"b"}},.5},
  {"missing tenant",[]Sample{{ID:"x"}},.5},
  {"nan score",[]Sample{{ID:"x",Tenant:"a",Score:math.NaN()}},.5},
  {"inf threshold",[]Sample{{ID:"x",Tenant:"a"}},math.Inf(1)},
 }
 for _,tc:=range cases{t.Run(tc.name,func(t *testing.T){if _,err:=Evaluate(tc.samples,tc.threshold);err==nil{t.Fatal("expected validation failure")}})}
}
func TestSweepSortedAndNoDuplicate(t *testing.T){
 s:=[]Sample{{ID:"x",Tenant:"a",Spam:true,Score:.5}}
 reports,err:=Sweep(s,[]float64{.9,.1,.5});if err!=nil{t.Fatal(err)}
 if len(reports)!=3||reports[0].Threshold!=.1||reports[1].Threshold!=.5||reports[2].Threshold!=.9{t.Fatalf("%+v",reports)}
 if _,err:=Sweep(s,[]float64{.5,.5});err==nil{t.Fatal("duplicate threshold accepted")}
}
func TestZeroDenominators(t *testing.T){
 r,err:=Evaluate([]Sample{{ID:"clean",Tenant:"a",Score:0}},1);if err!=nil{t.Fatal(err)}
 if r.Overall.Precision!=0||r.Overall.Recall!=0||r.Overall.FalsePositiveRate!=0{t.Fatalf("%+v",r.Overall)}
}
