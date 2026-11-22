package spooltrend

import (
 "strings"
 "testing"
 "time"
)

func TestHistoryRejectsDeadBaselineWithoutGrowth(t *testing.T) {
 now:=time.Date(2026,11,21,23,0,0,0,time.UTC)
 samples:=[]Snapshot{
  seriesSample(now.Add(-2*time.Minute),2,7),
  seriesSample(now.Add(-time.Minute),2,7),
 }
 policy:=Policy{MaxQueuedGrowth:-1,MaxDeadGrowth:-1,MaxDeliveringGrowth:-1,MaxPendingGrowth:-1,MaxDeadCount:3}
 got,err:=AnalyzeSeries(samples,policy,FreshnessPolicy{},now)
 if err!=nil {t.Fatal(err)}
 if got.GatePassed || got.FailedIntervals!=1 || len(got.GateFailures)!=2 {
  t.Fatalf("baseline and interval dead count must both fail: %+v",got)
 }
 if !strings.Contains(got.GateFailures[1],"sample_0: dead_count=7") {
  t.Fatalf("missing baseline evidence: %v",got.GateFailures)
 }
 if got.PeakDead!=7 {t.Fatalf("incorrect peak: %d",got.PeakDead)}
}

func TestHistoryTimelineContainsEveryBoundedObservation(t *testing.T) {
 now:=time.Date(2026,11,21,23,0,0,0,time.UTC)
 samples:=[]Snapshot{
  seriesSample(now.Add(-3*time.Minute),1,0),
  seriesSample(now.Add(-2*time.Minute),8,1),
  seriesSample(now.Add(-time.Minute),2,0),
 }
 policy:=Policy{MaxQueuedGrowth:-1,MaxDeadGrowth:-1,MaxDeliveringGrowth:-1,MaxPendingGrowth:-1,MaxDeadCount:-1}
 got,err:=AnalyzeSeries(samples,policy,FreshnessPolicy{},now)
 if err!=nil {t.Fatal(err)}
 if len(got.Points)!=3 {t.Fatalf("timeline has %d points",len(got.Points))}
 for i,p:=range got.Points {
  if !p.CapturedAt.Equal(samples[i].CapturedAt) || p.Queued!=samples[i].States["queued"] || p.Dead!=samples[i].States["dead"] {
   t.Fatalf("point %d mismatch: %+v",i,p)
  }
 }
 if got.PeakQueued!=8 || got.LargestQueuedIncrease!=7 {t.Fatalf("peak mismatch: %+v",got)}
}
