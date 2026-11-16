package qualification

import (
 "errors"
 "fmt"
 "math"
 "sort"
)

// GateConfig defines a conservative false-positive acceptance policy.
// Confidence is a one-sided Wilson score bound; it does not replace a representative corpus.
type GateConfig struct {
 MaxFalsePositiveRate float64 `json:"max_false_positive_rate"`
 MinCleanSamples int `json:"min_clean_samples"`
 ZScore float64 `json:"z_score"`
}
type GateResult struct {
 Tenant string `json:"tenant"`
 CleanSamples int `json:"clean_samples"`
 FalsePositives int `json:"false_positives"`
 ObservedFalsePositiveRate float64 `json:"observed_false_positive_rate"`
 UpperFalsePositiveRate float64 `json:"upper_false_positive_rate"`
 Passed bool `json:"passed"`
 Reasons []string `json:"reasons,omitempty"`
}
type GateReport struct {
 Config GateConfig `json:"config"`
 Overall GateResult `json:"overall"`
 Tenants []GateResult `json:"tenants"`
 Passed bool `json:"passed"`
}
func (c GateConfig) validate() error {
 if math.IsNaN(c.MaxFalsePositiveRate)||math.IsInf(c.MaxFalsePositiveRate,0)||c.MaxFalsePositiveRate<0||c.MaxFalsePositiveRate>1 {return errors.New("max false-positive rate must be finite and between 0 and 1")}
 if c.MinCleanSamples<1 {return errors.New("minimum clean samples must be positive")}
 if math.IsNaN(c.ZScore)||math.IsInf(c.ZScore,0)||c.ZScore<=0||c.ZScore>10 {return errors.New("z score must be finite and in (0,10]")}
 return nil
}
// WilsonUpper returns the upper endpoint of a binomial Wilson score interval.
func WilsonUpper(positives,total int,z float64) (float64,error) {
 if total<=0||positives<0||positives>total||math.IsNaN(z)||math.IsInf(z,0)||z<=0||z>10 {return 0,errors.New("invalid Wilson interval arguments")}
 n:=float64(total); p:=float64(positives)/n; z2:=z*z
 upper:=(p+z2/(2*n)+z*math.Sqrt(p*(1-p)/n+z2/(4*n*n)))/(1+z2/n)
 return math.Min(1,upper),nil
}
func gate(tenant string,m Metrics,c GateConfig) GateResult {
 n:=m.TrueNegative+m.FalsePositive
 r:=GateResult{Tenant:tenant,CleanSamples:n,FalsePositives:m.FalsePositive,ObservedFalsePositiveRate:m.FalsePositiveRate}
 if n>0 {r.UpperFalsePositiveRate,_=WilsonUpper(m.FalsePositive,n,c.ZScore)}
 if n<c.MinCleanSamples {r.Reasons=append(r.Reasons,fmt.Sprintf("insufficient clean samples: %d < %d",n,c.MinCleanSamples))}
 if n>0 && r.UpperFalsePositiveRate>c.MaxFalsePositiveRate {r.Reasons=append(r.Reasons,fmt.Sprintf("upper false-positive bound %.6f exceeds %.6f",r.UpperFalsePositiveRate,c.MaxFalsePositiveRate))}
 r.Passed=len(r.Reasons)==0
 return r
}
// AssessGates rejects overall success if any tenant fails; a large tenant cannot mask a small one.
func AssessGates(report Report,c GateConfig)(GateReport,error){
 if err:=c.validate();err!=nil{return GateReport{},err}
 if len(report.ByTenant)==0 {return GateReport{},errors.New("report has no tenants")}
 out:=GateReport{Config:c,Overall:gate("overall",report.Overall,c)}
 keys:=make([]string,0,len(report.ByTenant));for k:=range report.ByTenant{keys=append(keys,k)};sort.Strings(keys)
 out.Passed=out.Overall.Passed
 for _,k:=range keys {r:=gate(k,report.ByTenant[k],c);out.Tenants=append(out.Tenants,r);if !r.Passed{out.Passed=false}}
 return out,nil
}
