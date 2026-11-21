package spooltrend

import (
 "errors"
 "fmt"
 "sort"
)

// Policy contains optional operational growth limits. A limit of -1 disables
// that check. Growth is calculated from independently qualified snapshots.
type Policy struct {
 MaxQueuedGrowth int
 MaxDeadGrowth int
 MaxDeliveringGrowth int
 MaxPendingGrowth int
 MaxDeadCount int
}

func (p Policy) Validate() error {
 for name, value := range map[string]int{
  "max-queue-growth":p.MaxQueuedGrowth,
  "max-dead-growth":p.MaxDeadGrowth,
  "max-delivering-growth":p.MaxDeliveringGrowth,
  "max-pending-growth":p.MaxPendingGrowth,
  "max-dead-count":p.MaxDeadCount,
 } {
  if value < -1 { return fmt.Errorf("%s must be >= -1",name) }
 }
 return nil
}

// CompareWithPolicy validates both inputs before evaluating any limits.
// No SMTP message state is mutated by this operation.
func CompareWithPolicy(before, after Snapshot, p Policy) (Result,error) {
 if err:=p.Validate();err!=nil{return Result{},err}
 r,err:=Compare(before,after,p.MaxQueuedGrowth,p.MaxDeadGrowth)
 if err!=nil{return Result{},err}
 if p.MaxDeliveringGrowth>=0 && r.DeliveringDelta>p.MaxDeliveringGrowth {
  r.GateFailures=append(r.GateFailures,fmt.Sprintf("delivering_growth=%d exceeds max-delivering-growth=%d",r.DeliveringDelta,p.MaxDeliveringGrowth))
 }
 if p.MaxPendingGrowth>=0 && r.PendingDelta>p.MaxPendingGrowth {
  r.GateFailures=append(r.GateFailures,fmt.Sprintf("pending_growth=%d exceeds max-pending-growth=%d",r.PendingDelta,p.MaxPendingGrowth))
 }
 if p.MaxDeadCount>=0 && after.States["dead"]>p.MaxDeadCount {
  r.GateFailures=append(r.GateFailures,fmt.Sprintf("dead_count=%d exceeds max-dead-count=%d",after.States["dead"],p.MaxDeadCount))
 }
 sort.Strings(r.GateFailures)
 r.GatePassed=len(r.GateFailures)==0
 return r,nil
}

var _ = errors.New
