package spooltrend

import (
 "strings"
 "testing"
 "time"
)

func seriesSample(at time.Time, queued,dead int) Snapshot {
 clean:=true
 return Snapshot{CapturedAt:at,GatePassed:&clean,GateFailures:[]string{},Examined:queued+dead,Published:queued+dead,States:map[string]int{"queued":queued,"dead":dead},Findings:nil}
}

func TestSeriesDetectsTransientGrowthHiddenByEndpoints(t *testing.T) {
 now:=time.Date(2026,11,21,20,0,0,0,time.UTC)
 samples:=[]Snapshot{
  seriesSample(now.Add(-3*time.Hour),1,0),
  seriesSample(now.Add(-2*time.Hour),9,2),
  seriesSample(now.Add(-time.Hour),1,0),
 }
 p:=Policy{MaxQueuedGrowth:3,MaxDeadGrowth:1,MaxDeliveringGrowth:-1,MaxPendingGrowth:-1,MaxDeadCount:-1}
 r,err:=AnalyzeSeries(samples,p,FreshnessPolicy{RequireTimestamps:true},now)
 if err!=nil{t.Fatal(err)}
 if r.GatePassed || r.FailedIntervals!=1 || r.PeakQueued!=9 || r.PeakDead!=2 || r.LargestQueuedIncrease!=8 || r.LargestDeadIncrease!=2 {
  t.Fatalf("missed intermediate queue surge: %+v",r)
 }
 if len(r.GateFailures)!=2 || !strings.Contains(r.GateFailures[0],"interval_1") {t.Fatalf("missing interval evidence: %+v",r.GateFailures)}
}

func TestSeriesChronologyAndBoundaries(t *testing.T) {
 now:=time.Date(2026,11,21,20,0,0,0,time.UTC)
 a:=seriesSample(now.Add(-2*time.Hour),2,0)
 b:=seriesSample(now.Add(-time.Hour),3,0)
 p:=Policy{MaxQueuedGrowth:1,MaxDeadGrowth:-1,MaxDeliveringGrowth:-1,MaxPendingGrowth:-1,MaxDeadCount:-1}
 cases:=[]struct{name string;samples []Snapshot;freshness FreshnessPolicy;wantError bool}{
  {"valid",[]Snapshot{a,b},FreshnessPolicy{MaxSnapshotAge:time.Hour},false},
  {"reversed",[]Snapshot{b,a},FreshnessPolicy{},true},
  {"equal timestamps",[]Snapshot{a,a},FreshnessPolicy{},true},
  {"missing timestamp",[]Snapshot{a,seriesSample(time.Time{},3,0)},FreshnessPolicy{},true},
  {"stale",[]Snapshot{a,b},FreshnessPolicy{MaxSnapshotAge:time.Minute},true},
  {"excessive gap",[]Snapshot{a,b},FreshnessPolicy{MaxSnapshotGap:time.Minute},true},
  {"single sample",[]Snapshot{a},FreshnessPolicy{},true},
  {"no samples",nil,FreshnessPolicy{},true},
 }
 for _,tc:=range cases {
  t.Run(tc.name,func(t *testing.T){
   r,err:=AnalyzeSeries(tc.samples,p,tc.freshness,now)
   if (err!=nil)!=tc.wantError {t.Fatalf("result=%+v err=%v",r,err)}
   if !tc.wantError && (!r.GatePassed || r.Samples!=2 || r.LargestQueuedIncrease!=1){t.Fatalf("unexpected result: %+v",r)}
  })
 }
}

func TestSeriesRejectsUnqualifiedMiddleObservation(t *testing.T) {
 now:=time.Date(2026,11,21,20,0,0,0,time.UTC)
 samples:=[]Snapshot{seriesSample(now.Add(-3*time.Hour),1,0),seriesSample(now.Add(-2*time.Hour),2,0),seriesSample(now.Add(-time.Hour),1,0)}
 samples[1].UnreadableRecords=1
 _,err:=AnalyzeSeries(samples,Policy{MaxQueuedGrowth:-1,MaxDeadGrowth:-1,MaxDeliveringGrowth:-1,MaxPendingGrowth:-1,MaxDeadCount:-1},FreshnessPolicy{},now)
 if err==nil || !strings.Contains(err.Error(),"sample 1"){t.Fatalf("expected middle sample rejection, got %v",err)}
}

func TestSeriesRejectsExcessiveSamples(t *testing.T) {
 samples:=make([]Snapshot,1025)
 _,err:=AnalyzeSeries(samples,Policy{},FreshnessPolicy{},time.Now())
 if err==nil{t.Fatal("accepted unbounded history")}
}
