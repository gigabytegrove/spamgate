package spooltrend

import (
 "fmt"
)

// SustainedPolicy detects persistent queue pressure rather than a single spike.
// A disabled threshold is -1. MinSamples is the number of consecutive
// observations exceeding the threshold, inclusive of the first observation.
type SustainedPolicy struct {
 MaxQueued int
 MaxDelivering int
 MaxPending int
 MinSamples int
}

func (p SustainedPolicy) Validate() error {
 if p.MinSamples < 2 || p.MinSamples > 1024 {
  return fmt.Errorf("min-sustained-samples must be between 2 and 1024")
 }
 for _, v := range []struct{name string; limit int}{
  {"max-sustained-queued",p.MaxQueued},
  {"max-sustained-delivering",p.MaxDelivering},
  {"max-sustained-pending",p.MaxPending},
 } {
  if v.limit < -1 {return fmt.Errorf("%s must be >= -1",v.name)}
 }
 return nil
}

// ApplySustainedPolicy appends a single failure per qualifying continuous
// breach run. The input result is not modified.
func ApplySustainedPolicy(r SeriesResult,p SustainedPolicy)(SeriesResult,error){
 if err:=p.Validate();err!=nil{return SeriesResult{},err}
 if r.Samples<2 || r.Samples>1024 || len(r.Points)!=r.Samples {
  return SeriesResult{},fmt.Errorf("incomplete series evidence")
 }
 r.GateFailures=append([]string(nil),r.GateFailures...)
 for _,metric:=range []struct{name string; limit int; value func(SeriesPoint)int}{
  {"queued",p.MaxQueued,func(s SeriesPoint)int{return s.Queued}},
  {"delivering",p.MaxDelivering,func(s SeriesPoint)int{return s.Delivering}},
  {"pending",p.MaxPending,func(s SeriesPoint)int{return s.Pending}},
 } {
  start:=-1
  flush:=func(end int) {
   if start>=0 && end-start>=p.MinSamples {
    r.GateFailures=append(r.GateFailures,fmt.Sprintf("sustained_%s: samples_%d_to_%d exceed max-sustained-%s=%d (%d consecutive)",metric.name,start,end-1,metric.name,metric.limit,end-start))
   }
  }
  for i,point:=range r.Points {
   value:=metric.value(point)
   if value<0{return SeriesResult{},fmt.Errorf("sample %d: negative %s",i,metric.name)}
   if metric.limit>=0 && value>metric.limit {
    if start<0{start=i}
   } else if start>=0 {
    flush(i)
    start=-1
   }
  }
  flush(len(r.Points))
 }
 r.GatePassed=len(r.GateFailures)==0
 return r,nil
}
