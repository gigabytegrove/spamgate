package spooltrend

import (
 "fmt"
 "time"
)

// DurationPressurePolicy requires a pressure breach to persist across a
// measured capture interval. A zero duration disables the corresponding gate.
// This supplements sample-count checks; it never changes mail disposition.
type DurationPressurePolicy struct {
 Queued time.Duration
 Delivering time.Duration
 Pending time.Duration
}

func (p DurationPressurePolicy) Validate() error {
 for _, v := range []struct{name string; duration time.Duration}{
  {"min-queued-pressure-duration",p.Queued},
  {"min-delivering-pressure-duration",p.Delivering},
  {"min-pending-pressure-duration",p.Pending},
 } {
  if v.duration<0 {return fmt.Errorf("%s cannot be negative",v.name)}
 }
 return nil
}

// ApplyDurationPressure requires a threshold strictly greater than the limit
// at both ends of a contiguous interval. Capture gaps are not interpolated:
// the duration measures elapsed wall time between actual observations.
func ApplyDurationPressure(r SeriesResult, limits SeriesCeilings, policy DurationPressurePolicy)(SeriesResult,error){
 if err:=limits.Validate();err!=nil{return SeriesResult{},err}
 if err:=policy.Validate();err!=nil{return SeriesResult{},err}
 if r.Samples<2 || r.Samples>1024 || len(r.Points)!=r.Samples {return SeriesResult{},fmt.Errorf("incomplete series evidence")}
 r.GateFailures=append([]string(nil),r.GateFailures...)
 for i,point:=range r.Points {
  if point.Queued<0 || point.Delivering<0 || point.Pending<0 {return SeriesResult{},fmt.Errorf("sample %d: negative pressure count",i)}
  if point.CapturedAt.IsZero() {return SeriesResult{},fmt.Errorf("sample %d: missing capture timestamp",i)}
  if i>0 && !point.CapturedAt.After(r.Points[i-1].CapturedAt) {return SeriesResult{},fmt.Errorf("sample %d: unordered capture timestamp",i)}
 }
 for _,metric:=range []struct{name string; limit int; duration time.Duration; value func(SeriesPoint)int}{
  {"queued",limits.MaxQueued,policy.Queued,func(p SeriesPoint)int{return p.Queued}},
  {"delivering",limits.MaxDelivering,policy.Delivering,func(p SeriesPoint)int{return p.Delivering}},
  {"pending",limits.MaxPending,policy.Pending,func(p SeriesPoint)int{return p.Pending}},
 } {
  if metric.duration==0 || metric.limit<0 {continue}
  start:=-1
  flush:=func(end int) {
   if start<0 || end-start<2{return}
   elapsed:=r.Points[end-1].CapturedAt.Sub(r.Points[start].CapturedAt)
   if elapsed>=metric.duration {
    r.GateFailures=append(r.GateFailures,fmt.Sprintf("duration_%s: samples_%d_to_%d exceeded %d for %s (minimum %s)",metric.name,start,end-1,metric.limit,elapsed,metric.duration))
   }
  }
  for i,p:=range r.Points {
   if metric.value(p)>metric.limit {
    if start<0 {start=i}
   }else if start>=0 {
    flush(i)
    start=-1
   }
  }
  flush(len(r.Points))
 }
 r.GatePassed=len(r.GateFailures)==0
 return r,nil
}
