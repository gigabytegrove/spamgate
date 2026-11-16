package qualification

import (
 "fmt"
 "math"
 "sort"
)

// BoundaryAudit identifies score concentration near a proposed decision threshold.
// This is descriptive evidence, not a classifier accuracy or stability guarantee.
type BoundaryAudit struct {
 Threshold float64 `json:"threshold"`
 Margin float64 `json:"margin"`
 TotalNear int `json:"total_near"`
 ExactTies int `json:"exact_ties"`
 Tenants []TenantBoundaryAudit `json:"tenants"`
}
type TenantBoundaryAudit struct {
 Tenant string `json:"tenant"`
 Total int `json:"total"`
 Near int `json:"near"`
 SpamNear int `json:"spam_near"`
 CleanNear int `json:"clean_near"`
 ExactTies int `json:"exact_ties"`
 NearFraction float64 `json:"near_fraction"`
}

// AuditBoundary counts scores within an inclusive absolute margin. Subtraction
// is used only after finite inputs are validated, and overflow is handled.
func AuditBoundary(samples []Sample, threshold, margin float64) (BoundaryAudit, error) {
 if err:=Validate(samples,threshold);err!=nil{return BoundaryAudit{},err}
 if math.IsNaN(margin)||math.IsInf(margin,0)||margin<0{return BoundaryAudit{},fmt.Errorf("margin must be finite and nonnegative")}
 result:=BoundaryAudit{Threshold:threshold,Margin:margin}
 counts:=make(map[string]TenantBoundaryAudit)
 for _,s:=range samples {
  t:=counts[s.Tenant];t.Tenant=s.Tenant;t.Total++
  distance:=math.Abs(s.Score-threshold)
  if s.Score==threshold {t.ExactTies++;result.ExactTies++}
  if distance<=margin {
   t.Near++;result.TotalNear++
   if s.Spam {t.SpamNear++} else {t.CleanNear++}
  }
  counts[s.Tenant]=t
 }
 keys:=make([]string,0,len(counts))
 for key:=range counts {keys=append(keys,key)}
 sort.Strings(keys)
 for _,key:=range keys {
  t:=counts[key]
  t.NearFraction=float64(t.Near)/float64(t.Total)
  result.Tenants=append(result.Tenants,t)
 }
 return result,nil
}
