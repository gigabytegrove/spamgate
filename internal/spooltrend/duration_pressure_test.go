package spooltrend

import (
 "strings"
 "testing"
 "time"
)

func TestDurationPressure(t *testing.T){
 base:=time.Date(2026,11,22,0,0,0,0,time.UTC)
 r:=SeriesResult{Samples:5,GatePassed:true,Points:[]SeriesPoint{
  {CapturedAt:base,Queued:0},
  {CapturedAt:base.Add(time.Minute),Queued:6},
  {CapturedAt:base.Add(4*time.Minute),Queued:6},
  {CapturedAt:base.Add(5*time.Minute),Queued:6},
  {CapturedAt:base.Add(6*time.Minute),Queued:0},
 }}
 limits:=SeriesCeilings{MaxQueued:5,MaxDelivering:-1,MaxPending:-1}
 got,err:=ApplyDurationPressure(r,limits,DurationPressurePolicy{Queued:4*time.Minute})
 if err!=nil || got.GatePassed || len(got.GateFailures)!=1 || !strings.Contains(got.GateFailures[0],"samples_1_to_3"){t.Fatalf("boundary failed: %+v %v",got,err)}
 got,err=ApplyDurationPressure(r,limits,DurationPressurePolicy{Queued:5*time.Minute})
 if err!=nil || !got.GatePassed {t.Fatalf("short pressure failed: %+v %v",got,err)}
 if !r.GatePassed || len(r.GateFailures)!=0 {t.Fatal("mutated input")}
}

func TestDurationPressureInvalidEvidence(t *testing.T){
 base:=time.Now().UTC()
 r:=SeriesResult{Samples:2,Points:[]SeriesPoint{{CapturedAt:base},{CapturedAt:base}}}
 limits:=SeriesCeilings{MaxQueued:-1,MaxDelivering:-1,MaxPending:-1}
 if _,err:=ApplyDurationPressure(r,limits,DurationPressurePolicy{});err==nil {t.Fatal("accepted repeated timestamp")}
 r.Points[1].CapturedAt=base.Add(time.Second)
 if _,err:=ApplyDurationPressure(r,limits,DurationPressurePolicy{Queued:-time.Second});err==nil {t.Fatal("accepted negative duration")}
 r.Points[1].Pending=-1
 if _,err:=ApplyDurationPressure(r,limits,DurationPressurePolicy{});err==nil {t.Fatal("accepted negative count")}
}

func TestDurationPressurePreservesFailures(t *testing.T){
 base:=time.Now().UTC()
 r:=SeriesResult{Samples:2,GateFailures:[]string{"prior"},Points:[]SeriesPoint{{CapturedAt:base},{CapturedAt:base.Add(time.Minute)}}}
 got,err:=ApplyDurationPressure(r,SeriesCeilings{MaxQueued:-1,MaxDelivering:-1,MaxPending:-1},DurationPressurePolicy{})
 if err!=nil || got.GatePassed || len(got.GateFailures)!=1 {t.Fatalf("prior failure lost: %+v %v",got,err)}
 got.GateFailures[0]="changed"
 if r.GateFailures[0]!="prior" {t.Fatal("failure alias")}
}
