package spooltrend

import (
 "fmt"
)

// SeriesCeilings applies absolute operational limits to every captured
// observation, including the baseline. -1 disables an individual limit.
// This is read-only evidence qualification, not mail disposition.
type SeriesCeilings struct {
 MaxQueued int
 MaxDelivering int
 MaxPending int
}

func (c SeriesCeilings) Validate() error {
 for _, item := range []struct{name string; value int}{
  {"max-queued-count",c.MaxQueued},
  {"max-delivering-count",c.MaxDelivering},
  {"max-pending-count",c.MaxPending},
 } {
  if item.value < -1 {return fmt.Errorf("%s must be >= -1",item.name)}
 }
 return nil
}

// ApplySeriesCeilings preserves all existing growth and dead-letter failures,
// while adding absolute ceiling failures in chronological sample order.
func ApplySeriesCeilings(r SeriesResult, c SeriesCeilings) (SeriesResult,error) {
 if err:=c.Validate();err!=nil{return SeriesResult{},err}
 if len(r.Points)!=r.Samples || len(r.Points)<2 || len(r.Points)>1024 {
  return SeriesResult{},fmt.Errorf("incomplete series evidence")
 }
 for i,p:=range r.Points {
  for _, item := range []struct{name string; value,limit int}{
   {"queued_count",p.Queued,c.MaxQueued},
   {"delivering_count",p.Delivering,c.MaxDelivering},
   {"pending_count",p.Pending,c.MaxPending},
  } {
   if item.value<0 {return SeriesResult{},fmt.Errorf("sample %d: negative %s",i,item.name)}
   if item.limit>=0 && item.value>item.limit {
    r.GateFailures=append(r.GateFailures,fmt.Sprintf("sample_%d: %s=%d exceeds max-%s=%d",i,item.name,item.value,item.name,item.limit))
   }
  }
 }
 r.GatePassed=len(r.GateFailures)==0
 return r,nil
}
