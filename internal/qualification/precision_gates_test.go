package qualification

import (
 "math"
 "strings"
 "testing"
)

func TestPrecisionGateTenantIsolation(t *testing.T){
 samples:=[]Sample{}
 for i:=0;i<120;i++{
  samples=append(samples,Sample{ID:"good"+itoa(i),Tenant:"good",Spam:true,Score:9})
  samples=append(samples,Sample{ID:"bad"+itoa(i),Tenant:"bad",Spam:false,Score:9})
 }
 report,err:=Evaluate(samples,5);if err!=nil{t.Fatal(err)}
 result,err:=AssessPrecisionGates(report,PrecisionGateConfig{MinPrecision:.4,MinPredictedSpam:50,ZScore:1.6448536269514722})
 if err!=nil{t.Fatal(err)}
 if result.Passed || len(result.Tenants)!=2 || result.Tenants[0].Tenant!="bad" || result.Tenants[0].Passed || !result.Tenants[1].Passed {t.Fatalf("unexpected tenant precision: %+v",result)}
}
func TestPrecisionGateInsufficientAndZeroPredictions(t *testing.T){
 report,err:=Evaluate([]Sample{{ID:"a",Tenant:"a",Spam:true,Score:0}},5);if err!=nil{t.Fatal(err)}
 result,err:=AssessPrecisionGates(report,PrecisionGateConfig{MinPrecision:0,MinPredictedSpam:1,ZScore:1.64})
 if err!=nil{t.Fatal(err)}
 if result.Passed || !strings.Contains(result.Overall.Reasons[0],"insufficient") {t.Fatalf("zero predictions must fail: %+v",result)}
}
func TestPrecisionGateInvalidConfiguration(t *testing.T){
 report,err:=Evaluate([]Sample{{ID:"a",Tenant:"a",Spam:true,Score:9}},5);if err!=nil{t.Fatal(err)}
 for _,c:=range []PrecisionGateConfig{
  {MinPrecision:math.NaN(),MinPredictedSpam:1,ZScore:1},
  {MinPrecision:1.1,MinPredictedSpam:1,ZScore:1},
  {MinPrecision:.5,MinPredictedSpam:0,ZScore:1},
  {MinPrecision:.5,MinPredictedSpam:1,ZScore:math.Inf(1)},
 }{
  if _,err:=AssessPrecisionGates(report,c);err==nil{t.Fatalf("accepted invalid config: %+v",c)}
 }
}
func itoa(i int)string{return string(rune('a'+i/26))+string(rune('a'+i%26))}
