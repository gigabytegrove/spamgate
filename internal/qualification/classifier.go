// Package qualification provides deterministic, offline classifier acceptance metrics.
// It never changes live policy or message disposition.
package qualification

import (
 "errors"
 "fmt"
 "math"
 "sort"
)

type Sample struct {
 ID string `json:"id"`
 Tenant string `json:"tenant"`
 Spam bool `json:"spam"`
 Score float64 `json:"score"`
}
type Counts struct {
 TruePositive int `json:"true_positive"`
 FalsePositive int `json:"false_positive"`
 TrueNegative int `json:"true_negative"`
 FalseNegative int `json:"false_negative"`
}
type Metrics struct {
 Counts
 Precision float64 `json:"precision"`
 Recall float64 `json:"recall"`
 FalsePositiveRate float64 `json:"false_positive_rate"`
 FalseNegativeRate float64 `json:"false_negative_rate"`
}
type Report struct {
 Threshold float64 `json:"threshold"`
 Overall Metrics `json:"overall"`
 ByTenant map[string]Metrics `json:"by_tenant"`
}
func Validate(samples []Sample, threshold float64) error {
 if math.IsNaN(threshold) || math.IsInf(threshold,0) { return errors.New("threshold must be finite") }
 if len(samples)==0 { return errors.New("corpus is empty") }
 seen:=make(map[string]struct{},len(samples))
 for i,s:=range samples {
  if s.ID=="" || s.Tenant=="" { return fmt.Errorf("sample %d: ID and tenant required",i) }
  if _,ok:=seen[s.ID];ok { return fmt.Errorf("duplicate sample ID %q",s.ID) }
  seen[s.ID]=struct{}{}
  if math.IsNaN(s.Score)||math.IsInf(s.Score,0) { return fmt.Errorf("sample %q: score must be finite",s.ID) }
 }
 return nil
}
func measure(c Counts) Metrics {
 m:=Metrics{Counts:c}
 if n:=c.TruePositive+c.FalsePositive;n>0 { m.Precision=float64(c.TruePositive)/float64(n) }
 if n:=c.TruePositive+c.FalseNegative;n>0 { m.Recall=float64(c.TruePositive)/float64(n);m.FalseNegativeRate=float64(c.FalseNegative)/float64(n) }
 if n:=c.FalsePositive+c.TrueNegative;n>0 { m.FalsePositiveRate=float64(c.FalsePositive)/float64(n) }
 return m
}
func add(c *Counts,spam,predicted bool) {
 switch {
 case spam && predicted:c.TruePositive++
 case spam:c.FalseNegative++
 case predicted:c.FalsePositive++
 default:c.TrueNegative++
 }
}
func Evaluate(samples []Sample,threshold float64)(Report,error){
 if err:=Validate(samples,threshold);err!=nil{return Report{},err}
 overall:=Counts{}
 per:=map[string]Counts{}
 for _,s:=range samples {
  predicted:=s.Score>=threshold
  add(&overall,s.Spam,predicted)
  c:=per[s.Tenant];add(&c,s.Spam,predicted);per[s.Tenant]=c
 }
 r:=Report{Threshold:threshold,Overall:measure(overall),ByTenant:make(map[string]Metrics,len(per))}
 for tenant,c:=range per {r.ByTenant[tenant]=measure(c)}
 return r,nil
}
// Sweep evaluates thresholds in sorted order. Duplicate thresholds are rejected.
func Sweep(samples []Sample,thresholds []float64)([]Report,error){
 if len(thresholds)==0{return nil,errors.New("no thresholds")}
 ts:=append([]float64(nil),thresholds...)
 sort.Float64s(ts)
 out:=make([]Report,0,len(ts))
 for i,t:=range ts {
  if i>0 && t==ts[i-1] {return nil,fmt.Errorf("duplicate threshold %g",t)}
  r,err:=Evaluate(samples,t);if err!=nil{return nil,err};out=append(out,r)
 }
 return out,nil
}
