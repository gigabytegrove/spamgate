package qualification

import (
 "math"
 "testing"
)
func TestWilsonLowerBoundaries(t *testing.T){
 v,err:=WilsonLower(0,100,1.6448536269514722)
 if err!=nil||v!=0 {t.Fatalf("zero positives: %v %v",v,err)}
 v,err=WilsonLower(100,100,1.6448536269514722)
 if err!=nil||v<=0.97||v>=1 {t.Fatalf("all positives: %v %v",v,err)}
 for _,tc:=range []struct{p,n int;z float64}{{-1,2,1},{3,2,1},{1,0,1},{1,2,0},{1,2,math.NaN()},{1,2,math.Inf(1)}} {
  if _,err:=WilsonLower(tc.p,tc.n,tc.z);err==nil {t.Fatalf("accepted invalid args %+v",tc)}
 }
}
func TestRecallGatesTenantIsolation(t *testing.T){
 r:=Report{Overall:measure(Counts{TruePositive:200,FalseNegative:1}),ByTenant:map[string]Metrics{
  "large":measure(Counts{TruePositive:200}),
  "small":measure(Counts{FalseNegative:1}),
 }}
 g,err:=AssessRecallGates(r,RecallGateConfig{MinRecall:0.8,MinSpamSamples:1,ZScore:1.6448536269514722})
 if err!=nil {t.Fatal(err)}
 if g.Passed||len(g.Tenants)!=2||g.Tenants[0].Tenant!="large"||g.Tenants[1].Tenant!="small"||g.Tenants[1].Passed {t.Fatalf("tenant failure masked: %+v",g)}
}
func TestRecallGateInsufficientSpam(t *testing.T){
 r:=Report{Overall:measure(Counts{TrueNegative:200}),ByTenant:map[string]Metrics{"empty":measure(Counts{TrueNegative:200})}}
 g,err:=AssessRecallGates(r,RecallGateConfig{MinRecall:0,MinSpamSamples:1,ZScore:1})
 if err!=nil||g.Passed||g.Overall.Passed||g.Tenants[0].Passed {t.Fatalf("empty spam passed: %+v %v",g,err)}
}
func TestRecallGateInvalidConfig(t *testing.T){
 r:=Report{ByTenant:map[string]Metrics{"a":{}}}
 for _,c:=range []RecallGateConfig{{MinRecall:-1,MinSpamSamples:1,ZScore:1},{MinRecall:math.NaN(),MinSpamSamples:1,ZScore:1},{MinRecall:0.5,MinSpamSamples:0,ZScore:1},{MinRecall:0.5,MinSpamSamples:1,ZScore:0}} {
  if _,err:=AssessRecallGates(r,c);err==nil {t.Fatalf("accepted invalid config: %+v",c)}
 }
}
