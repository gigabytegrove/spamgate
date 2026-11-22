package spooltrend

import (
 "strings"
 "testing"
)

func TestSeriesAbsoluteCeilingsEveryObservation(t *testing.T) {
 r:=SeriesResult{Samples:3,GatePassed:true,Points:[]SeriesPoint{
  {Queued:9,Delivering:1,Pending:0},
  {Queued:1,Delivering:7,Pending:8},
  {Queued:2,Delivering:0,Pending:0},
 }}
 got,err:=ApplySeriesCeilings(r,SeriesCeilings{MaxQueued:3,MaxDelivering:4,MaxPending:5})
 if err!=nil{t.Fatal(err)}
 if got.GatePassed || len(got.GateFailures)!=3{t.Fatalf("expected three failures: %+v",got)}
 for i,want:=range []string{"sample_0: queued_count=9","sample_1: delivering_count=7","sample_1: pending_count=8"} {
  if !strings.Contains(got.GateFailures[i],want){t.Fatalf("failure %d: %s",i,got.GateFailures[i])}
 }
 if r.GatePassed!=true || len(r.GateFailures)!=0{t.Fatal("original result mutated")}
}
func TestSeriesCeilingsBoundaryAndInvalid(t *testing.T){
 r:=SeriesResult{Samples:2,GatePassed:true,GateFailures:[]string{"prior failure"},Points:[]SeriesPoint{{Queued:3},{Queued:3}}}
 got,err:=ApplySeriesCeilings(r,SeriesCeilings{MaxQueued:3,MaxDelivering:-1,MaxPending:-1})
 if err!=nil || got.GatePassed || len(got.GateFailures)!=1{t.Fatalf("boundary/prior failure: %+v %v",got,err)}
 for _,c:=range []SeriesCeilings{{MaxQueued:-2},{MaxDelivering:-2},{MaxPending:-2}} {
  if _,err:=ApplySeriesCeilings(r,c);err==nil{t.Fatalf("accepted invalid ceiling: %+v",c)}
 }
 r.Points=r.Points[:1]
 if _,err:=ApplySeriesCeilings(r,SeriesCeilings{});err==nil{t.Fatal("accepted incomplete evidence")}
}
