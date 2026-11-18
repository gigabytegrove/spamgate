package qualification

import (
 "fmt"
 "testing"
)

func holdoutSamples(prefix string, tenants []string, cleanScore, spamScore float64) []Sample {
 var out []Sample
 for _,tenant:=range tenants {
  for i:=0;i<80;i++ {
   out=append(out,Sample{ID:fmt.Sprintf("%s-%s-clean-%d",prefix,tenant,i),Tenant:tenant,Score:cleanScore})
   out=append(out,Sample{ID:fmt.Sprintf("%s-%s-spam-%d",prefix,tenant,i),Tenant:tenant,Score:spamScore,Spam:true})
  }
 }
 return out
}
func holdoutGates()(GateConfig,PrecisionGateConfig,RecallGateConfig){
 return GateConfig{MaxFalsePositiveRate:0.1,MinCleanSamples:30,ZScore:1.96},
 PrecisionGateConfig{MinPrecision:0.8,MinPredictedSpam:30,ZScore:1.96},
 RecallGateConfig{MinRecall:0.8,MinSpamSamples:30,ZScore:1.96}
}
func TestIndependentHoldoutPassesFrozenThreshold(t *testing.T){
 fp,pr,re:=holdoutGates()
 out,err:=QualifyIndependentHoldout(holdoutSamples("tune",[]string{"a","b"},0.1,0.9),holdoutSamples("verify",[]string{"a","b"},0.2,0.8),[]float64{0.5,0.95},fp,pr,re)
 if err!=nil{t.Fatal(err)}
 if !out.Passed||out.Holdout==nil||out.Tuning.Selected==nil||out.Holdout.Threshold!=out.Tuning.Selected.Threshold{t.Fatalf("unexpected qualification: %+v",out)}
}
func TestIndependentHoldoutRejectsTenantDrift(t *testing.T){
 fp,pr,re:=holdoutGates()
 out,err:=QualifyIndependentHoldout(holdoutSamples("tune",[]string{"a","b"},0.1,0.9),holdoutSamples("verify",[]string{"a","c"},0.1,0.9),[]float64{0.5},fp,pr,re)
 if err!=nil{t.Fatal(err)}
 if out.Passed||len(out.MissingTenants)!=1||out.MissingTenants[0]!="b"||len(out.NewTenants)!=1||out.NewTenants[0]!="c"{t.Fatalf("tenant drift accepted: %+v",out)}
}
func TestIndependentHoldoutRejectsDegradedAccuracy(t *testing.T){
 fp,pr,re:=holdoutGates()
 out,err:=QualifyIndependentHoldout(holdoutSamples("tune",[]string{"a"},0.1,0.9),holdoutSamples("verify",[]string{"a"},0.9,0.1),[]float64{0.5},fp,pr,re)
 if err!=nil{t.Fatal(err)}
 if out.Passed||out.Holdout==nil||out.Holdout.Passed{t.Fatalf("degraded holdout passed: %+v",out)}
}
func TestIndependentHoldoutRejectsOverlapAndEmpty(t *testing.T){
 fp,pr,re:=holdoutGates()
 tune:=holdoutSamples("same",[]string{"a"},0.1,0.9)
 if _,err:=QualifyIndependentHoldout(tune,tune,[]float64{0.5},fp,pr,re);err==nil{t.Fatal("overlapping corpora accepted")}
 if _,err:=QualifyIndependentHoldout(tune,nil,[]float64{0.5},fp,pr,re);err==nil{t.Fatal("empty holdout accepted")}
}
func TestIndependentHoldoutDoesNotPromoteFailedTuning(t *testing.T){
 fp,pr,re:=holdoutGates()
 out,err:=QualifyIndependentHoldout(holdoutSamples("tune",[]string{"a"},0.9,0.1),holdoutSamples("verify",[]string{"a"},0.1,0.9),[]float64{0.5},fp,pr,re)
 if err!=nil{t.Fatal(err)}
 if out.Passed||out.Tuning.Selected!=nil||out.Holdout!=nil{t.Fatalf("failed tuning promoted: %+v",out)}
}
