package qualification

import (
 "math"
 "strconv"
 "testing"
)
func TestWilsonUpperConservative(t *testing.T){
 x,err:=WilsonUpper(0,100,1.6448536269514722);if err!=nil{t.Fatal(err)}
 if x<=0.02||x>=0.04{t.Fatalf("unexpected zero-event bound %f",x)}
 if _,err:=WilsonUpper(1,0,1.64);err==nil{t.Fatal("accepted zero denominator")}
 if _,err:=WilsonUpper(2,1,1.64);err==nil{t.Fatal("accepted impossible count")}
}
func TestTenantGateCannotBeMasked(t *testing.T){
 samples:=make([]Sample,0,202)
 for i:=0;i<200;i++{samples=append(samples,Sample{ID:fmtID("a",i),Tenant:"large",Score:0})}
 samples=append(samples,Sample{ID:"small-1",Tenant:"small",Score:0},{ID:"small-2",Tenant:"small",Score:10})
 r,err:=Evaluate(samples,5);if err!=nil{t.Fatal(err)}
 g,err:=AssessGates(r,GateConfig{MaxFalsePositiveRate:.1,MinCleanSamples:2,ZScore:1.645});if err!=nil{t.Fatal(err)}
 if g.Passed||!g.Overall.Passed||g.Tenants[0].Tenant!="large"||g.Tenants[1].Tenant!="small"||g.Tenants[1].Passed{t.Fatalf("incorrect tenant gate %+v",g)}
}
func fmtID(prefix string,i int)string{return prefix+"-"+strconv.Itoa(i)}
func TestGateRejectsInsufficientAndInvalid(t *testing.T){
 r,err:=Evaluate([]Sample{{ID:"x",Tenant:"t",Spam:true,Score:10}},5);if err!=nil{t.Fatal(err)}
 g,err:=AssessGates(r,GateConfig{MaxFalsePositiveRate:1,MinCleanSamples:1,ZScore:1.645});if err!=nil{t.Fatal(err)}
 if g.Passed||len(g.Tenants[0].Reasons)==0{t.Fatal("missing clean samples passed")}
 for _,c:=range []GateConfig{{MaxFalsePositiveRate:math.NaN(),MinCleanSamples:1,ZScore:1.6},{MaxFalsePositiveRate:.1,MinCleanSamples:0,ZScore:1.6},{MaxFalsePositiveRate:.1,MinCleanSamples:1,ZScore:0}}{
  if _,err:=AssessGates(r,c);err==nil{t.Fatalf("accepted invalid config %+v",c)}
 }
}
