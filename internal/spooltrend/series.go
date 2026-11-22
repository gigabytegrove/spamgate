package spooltrend

import (
 "errors"
 "fmt"
 "time"
)

// SeriesPoint is a bounded, privacy-preserving queue observation.
type SeriesPoint struct {
 CapturedAt time.Time `json:"captured_at"`
 Queued int `json:"queued"`
 Delivering int `json:"delivering"`
 Dead int `json:"dead"`
 Pending int `json:"pending"`
}

// SeriesResult summarizes consecutive qualified observations. It does not
// assert final mailbox delivery or make any changes to the queue.
type SeriesResult struct {
 GatePassed bool `json:"gate_passed"`
 GateFailures []string `json:"gate_failures"`
 Samples int `json:"samples"`
 First time.Time `json:"first"`
 Last time.Time `json:"last"`
 PeakQueued int `json:"peak_queued"`
 PeakDelivering int `json:"peak_delivering"`
 PeakDead int `json:"peak_dead"`
 PeakPending int `json:"peak_pending"`
 LargestQueuedIncrease int `json:"largest_queued_increase"`
 LargestDeadIncrease int `json:"largest_dead_increase"`
 LargestDeliveringIncrease int `json:"largest_delivering_increase"`
 LargestPendingIncrease int `json:"largest_pending_increase"`
 FailedIntervals int `json:"failed_intervals"`
}

// AnalyzeSeries checks every adjacent interval, not merely the endpoints.
// Every snapshot must be timestamped, internally clean and strictly ordered.
// Bounds avoid unbounded report processing in unattended diagnostics.
func AnalyzeSeries(samples []Snapshot, policy Policy, freshness FreshnessPolicy, now time.Time) (SeriesResult,error) {
 if len(samples)<2 || len(samples)>1024 { return SeriesResult{},errors.New("series requires 2 to 1024 snapshots") }
 if err:=policy.Validate();err!=nil{return SeriesResult{},err}
 if err:=freshness.Validate();err!=nil{return SeriesResult{},err}
 r:=SeriesResult{GatePassed:true,Samples:len(samples),First:samples[0].CapturedAt,Last:samples[len(samples)-1].CapturedAt,GateFailures:[]string{}}
 for i,s:=range samples {
  if err:=validateSnapshot(s);err!=nil{return SeriesResult{},fmt.Errorf("sample %d: %w",i,err)}
  if s.CapturedAt.IsZero(){return SeriesResult{},fmt.Errorf("sample %d: timestamp required",i)}
  if s.CapturedAt.After(now.Add(5*time.Minute)){return SeriesResult{},fmt.Errorf("sample %d: future timestamp",i)}
  if i==0 || s.States["queued"]>r.PeakQueued {r.PeakQueued=s.States["queued"]}
  if i==0 || s.States["delivering"]>r.PeakDelivering {r.PeakDelivering=s.States["delivering"]}
  if i==0 || s.States["dead"]>r.PeakDead {r.PeakDead=s.States["dead"]}
  if i==0 || s.Pending>r.PeakPending {r.PeakPending=s.Pending}
  if i==0 {continue}
  prev:=samples[i-1]
  if err:=CheckFreshness(prev,s,FreshnessPolicy{RequireTimestamps:true,MaxSnapshotGap:freshness.MaxSnapshotGap},now);err!=nil {
   return SeriesResult{},fmt.Errorf("interval %d: %w",i,err)
  }
  comparison,err:=CompareWithPolicy(prev,s,policy)
  if err!=nil{return SeriesResult{},fmt.Errorf("interval %d: %w",i,err)}
  if comparison.QueueDelta>r.LargestQueuedIncrease {r.LargestQueuedIncrease=comparison.QueueDelta}
  if comparison.DeadDelta>r.LargestDeadIncrease {r.LargestDeadIncrease=comparison.DeadDelta}
  if comparison.DeliveringDelta>r.LargestDeliveringIncrease {r.LargestDeliveringIncrease=comparison.DeliveringDelta}
  if comparison.PendingDelta>r.LargestPendingIncrease {r.LargestPendingIncrease=comparison.PendingDelta}
  if !comparison.GatePassed {
   r.FailedIntervals++
   for _,failure:=range comparison.GateFailures {
    r.GateFailures=append(r.GateFailures,fmt.Sprintf("interval_%d: %s",i,failure))
   }
  }
 }
 if freshness.MaxSnapshotAge>0 && now.Sub(r.Last)>freshness.MaxSnapshotAge {
  return SeriesResult{},fmt.Errorf("last snapshot age exceeds %s",freshness.MaxSnapshotAge)
 }
 r.GatePassed=len(r.GateFailures)==0
 return r,nil
}
