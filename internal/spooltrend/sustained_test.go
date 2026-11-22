package spooltrend

import (
 "strings"
 "testing"
)

func TestSustainedPolicyTransientAndPersistent(t *testing.T){
 r:=SeriesResult{Samples:7,GatePassed:true,Points:[]SeriesPoint{
  {Queued:1,Delivering:0,Pending:0},
  {Queued:8,Delivering:2,Pending:0},
  {Queued:1,Delivering:2,Pending:0},
  {Queued:9,Delivering:2,Pending:0},
  {Queued:9,Delivering:0,Pending:0},
  {Queued:9,Delivering:0,Pending:3},
  {Queued:0,Delivering:0,Pending:3},
 }}
 p:=SustainedPolicy{MaxQueued:5,MaxDelivering:1,MaxPending:2,MinSamples:3}
 got,err:=ApplySustainedPolicy(r,p)
 if err!=nil{t.Fatal(err)}
 if got.GatePassed || len(got.GateFailures)!=2 {t.Fatalf("unexpected result %+v",got)}
 if !strings.Contains(got.GateFailures[0],"samples_3_to_5") || !strings.Contains(got.GateFailures[1],"samples_1_to_3"){t.Fatalf("wrong runs: %v",got.GateFailures)}
 if !r.GatePassed || len(r.GateFailures)!=0{t.Fatal("input mutated")}
}

func TestSustainedPolicyDisabledBoundaryAndPreservation(t *testing.T){
 r:=SeriesResult{Samples:2,GatePassed:false,GateFailures:[]string{"existing"},Points:[]SeriesPoint{{Queued:5},{Queued:5}}}
 got,err:=ApplySustainedPolicy(r,SustainedPolicy{MaxQueued:5,MaxDelivering:-1,MaxPending:-1,MinSamples:2})
 if err!=nil || got.GatePassed || len(got.GateFailures)!=1 {t.Fatalf("unexpected result %+v %v",got,err)}
 got.GateFailures[0]="changed"
 if r.GateFailures[0]!="existing"{t.Fatal("aliased failures")}
}

func TestSustainedPolicyRejectsInvalidEvidence(t *testing.T){
 r:=SeriesResult{Samples:2,Points:[]SeriesPoint{{},{}}}
 for _,p:=range []SustainedPolicy{
  {MinSamples:1},{MinSamples:1025},{MinSamples:2,MaxQueued:-2},
 }{
  if _,err:=ApplySustainedPolicy(r,p);err==nil{t.Fatalf("accepted %+v",p)}
 }
 r.Points[1].Pending=-1
 if _,err:=ApplySustainedPolicy(r,SustainedPolicy{MinSamples:2,MaxQueued:-1,MaxDelivering:-1,MaxPending:-1});err==nil{t.Fatal("accepted negative evidence")}
 r.Points=r.Points[:1]
 if _,err:=ApplySustainedPolicy(r,SustainedPolicy{MinSamples:2});err==nil{t.Fatal("accepted incomplete series")}
}
