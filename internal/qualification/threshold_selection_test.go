package qualification

import (
 "math"
 "testing"
)

func TestThresholdSelectionRequiresEveryTenantAndEveryGate(t *testing.T) {
 samples:=[]Sample{}
 for _,tenant:=range []string{"alpha","beta"} {
  for i:=0;i<40;i++ {
   samples=append(samples,Sample{ID:tenant+"-clean-"+string(rune(1000+i)),Tenant:tenant,Score:0.1})
   samples=append(samples,Sample{ID:tenant+"-spam-"+string(rune(1000+i)),Tenant:tenant,Spam:true,Score:0.9})
  }
 }
 fp:=GateConfig{MaxFalsePositiveRate:0.2,MinCleanSamples:20,ZScore:1.96}
 pr:=PrecisionGateConfig{MinPrecision:0.8,MinPredictedSpam:20,ZScore:1.96}
 re:=RecallGateConfig{MinRecall:0.8,MinSpamSamples:20,ZScore:1.96}
 result,err:=SelectQualifiedThreshold(samples,[]float64{0.95,0.5,0.05},fp,pr,re)
 if err!=nil{t.Fatal(err)}
 if len(result.Candidates)!=3{t.Fatalf("candidates: %d",len(result.Candidates))}
 if result.Selected==nil||result.Selected.Threshold!=0.5{t.Fatalf("selection: %+v",result.Selected)}
 if result.Candidates[0].Passed||!result.Candidates[1].Passed||result.Candidates[2].Passed{t.Fatalf("unexpected gate outcomes: %+v",result.Candidates)}
 // A tiny tenant cannot be hidden by the aggregate corpus.
 samples=append(samples,Sample{ID:"gamma-clean",Tenant:"gamma",Score:0.1},Sample{ID:"gamma-spam",Tenant:"gamma",Spam:true,Score:0.9})
 result,err=SelectQualifiedThreshold(samples,[]float64{0.5},fp,pr,re)
 if err!=nil{t.Fatal(err)}
 if result.Selected!=nil||result.Candidates[0].Passed{t.Fatal("underpowered tenant passed")}
}

func TestThresholdSelectionInvalidInputAndNoPassingCandidate(t *testing.T) {
 s:=[]Sample{{ID:"a",Tenant:"t",Score:0.1},{ID:"b",Tenant:"t",Spam:true,Score:0.9}}
 fp:=GateConfig{MaxFalsePositiveRate:0,MinCleanSamples:100,ZScore:1.96}
 pr:=PrecisionGateConfig{MinPrecision:0.9,MinPredictedSpam:100,ZScore:1.96}
 re:=RecallGateConfig{MinRecall:0.9,MinSpamSamples:100,ZScore:1.96}
 out,err:=SelectQualifiedThreshold(s,[]float64{0.5},fp,pr,re)
 if err!=nil||out.Selected!=nil||len(out.Candidates)!=1{t.Fatalf("expected no qualifying threshold: %+v %v",out,err)}
 if _,err=SelectQualifiedThreshold(s,[]float64{math.NaN()},fp,pr,re);err==nil{t.Fatal("accepted NaN threshold")}
 if _,err=SelectQualifiedThreshold(s,[]float64{0.5,0.5},fp,pr,re);err==nil{t.Fatal("accepted duplicate threshold")}
}

func TestIndependentHoldoutRejectsReusedIDs(t *testing.T) {
 train:=[]Sample{{ID:"id1",Tenant:"a",Score:0.1}}
 hold:=[]Sample{{ID:"id1",Tenant:"b",Score:0.9}}
 if err:=ValidateIndependentHoldout(train,hold);err==nil{t.Fatal("accepted reused ID across tenants")}
 hold[0].ID="id2"
 if err:=ValidateIndependentHoldout(train,hold);err!=nil{t.Fatal(err)}
}
