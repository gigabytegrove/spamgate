package qualification

import (
 "errors"
 "fmt"
 "math"
 "sort"
)

// StabilityAudit measures the messages whose decisions change when the
// threshold moves from threshold-margin to threshold+margin. It does not
// alter the classifier, and is not a substitute for independent corpora.
type StabilityAudit struct {
 Threshold float64 `json:"threshold"`
 Margin float64 `json:"margin"`
 LowerThreshold float64 `json:"lower_threshold"`
 UpperThreshold float64 `json:"upper_threshold"`
 Total int `json:"total"`
 Flips int `json:"flips"`
 CleanFlips int `json:"clean_flips"`
 SpamFlips int `json:"spam_flips"`
 FlipFraction float64 `json:"flip_fraction"`
 MaxTenantFlipFraction float64 `json:"max_tenant_flip_fraction,omitempty"`
 Passed bool `json:"passed"`
 Tenants []TenantStability `json:"tenants"`
}
type TenantStability struct {
 Tenant string `json:"tenant"`
 Total int `json:"total"`
 Flips int `json:"flips"`
 CleanFlips int `json:"clean_flips"`
 SpamFlips int `json:"spam_flips"`
 FlipFraction float64 `json:"flip_fraction"`
 Passed bool `json:"passed"`
}

// AuditThresholdStability is an optional deterministic sensitivity gate.
// A negative maxTenantFlipFraction means descriptive-only audit. A gate
// checks every tenant independently, never hiding a weak tenant in averages.
func AuditThresholdStability(samples []Sample, threshold, margin, maxTenantFlipFraction float64) (StabilityAudit,error) {
 if err:=Validate(samples,threshold);err!=nil{return StabilityAudit{},err}
 if math.IsNaN(margin)||math.IsInf(margin,0)||margin<0{return StabilityAudit{},errors.New("stability margin must be finite and nonnegative")}
 if math.IsNaN(maxTenantFlipFraction)||math.IsInf(maxTenantFlipFraction,0)||maxTenantFlipFraction>1 || (maxTenantFlipFraction<0 && maxTenantFlipFraction!=-1) {
  return StabilityAudit{},errors.New("max tenant flip fraction must be -1 or within [0,1]")
 }
 lower,upper:=threshold-margin,threshold+margin
 if math.IsInf(lower,0)||math.IsInf(upper,0)||math.IsNaN(lower)||math.IsNaN(upper){
  return StabilityAudit{},errors.New("stability threshold bounds overflow")
 }
 audit:=StabilityAudit{Threshold:threshold,Margin:margin,LowerThreshold:lower,UpperThreshold:upper,Total:len(samples),Passed:true}
 if maxTenantFlipFraction>=0{audit.MaxTenantFlipFraction=maxTenantFlipFraction}
 tenants:=map[string]TenantStability{}
 for _,s:=range samples{
  t:=tenants[s.Tenant];t.Tenant=s.Tenant;t.Total++
  if s.Score>=lower && s.Score<upper {
   t.Flips++;audit.Flips++
   if s.Spam {t.SpamFlips++;audit.SpamFlips++} else {t.CleanFlips++;audit.CleanFlips++}
  }
  tenants[s.Tenant]=t
 }
 audit.FlipFraction=float64(audit.Flips)/float64(audit.Total)
 names:=make([]string,0,len(tenants))
 for name:=range tenants{names=append(names,name)}
 sort.Strings(names)
 for _,name:=range names {
  t:=tenants[name]
  t.FlipFraction=float64(t.Flips)/float64(t.Total)
  t.Passed=maxTenantFlipFraction<0 || t.FlipFraction<=maxTenantFlipFraction
  if !t.Passed{audit.Passed=false}
  audit.Tenants=append(audit.Tenants,t)
 }
 if len(audit.Tenants)==0{return StabilityAudit{},fmt.Errorf("no tenants")}
 return audit,nil
}
