package qualification

import (
 "errors"
 "fmt"
 "math"
 "sort"
)

// RecallGateConfig constrains false negatives with a one-sided Wilson lower
// confidence bound on recall. It is independent of the false-positive gate.
type RecallGateConfig struct {
 MinRecall float64 `json:"min_recall"`
 MinSpamSamples int `json:"min_spam_samples"`
 ZScore float64 `json:"z_score"`
}
type RecallGateResult struct {
 Tenant string `json:"tenant"`
 SpamSamples int `json:"spam_samples"`
 TruePositives int `json:"true_positives"`
 FalseNegatives int `json:"false_negatives"`
 ObservedRecall float64 `json:"observed_recall"`
 LowerRecall float64 `json:"lower_recall"`
 Passed bool `json:"passed"`
 Reasons []string `json:"reasons,omitempty"`
}
type RecallGateReport struct {
 Config RecallGateConfig `json:"config"`
 Overall RecallGateResult `json:"overall"`
 Tenants []RecallGateResult `json:"tenants"`
 Passed bool `json:"passed"`
}
func (c RecallGateConfig) validate() error {
 if math.IsNaN(c.MinRecall)||math.IsInf(c.MinRecall,0)||c.MinRecall<0||c.MinRecall>1 {return errors.New("minimum recall must be finite and between 0 and 1")}
 if c.MinSpamSamples<1 {return errors.New("minimum spam samples must be positive")}
 if math.IsNaN(c.ZScore)||math.IsInf(c.ZScore,0)||c.ZScore<=0||c.ZScore>10 {return errors.New("z score must be finite and in (0,10]")}
 return nil
}
// WilsonLower is the one-sided lower Wilson score confidence endpoint.
func WilsonLower(positives,total int,z float64)(float64,error){
 if total<=0||positives<0||positives>total||math.IsNaN(z)||math.IsInf(z,0)||z<=0||z>10 {return 0,errors.New("invalid Wilson interval arguments")}
 n:=float64(total);p:=float64(positives)/n;z2:=z*z
 lower:=(p+z2/(2*n)-z*math.Sqrt(p*(1-p)/n+z2/(4*n*n)))/(1+z2/n)
 return math.Max(0,lower),nil
}
func recallGate(tenant string,m Metrics,c RecallGateConfig) RecallGateResult {
 n:=m.TruePositive+m.FalseNegative
 r:=RecallGateResult{Tenant:tenant,SpamSamples:n,TruePositives:m.TruePositive,FalseNegatives:m.FalseNegative,ObservedRecall:m.Recall}
 if n>0 {r.LowerRecall,_=WilsonLower(m.TruePositive,n,c.ZScore)}
 if n<c.MinSpamSamples {r.Reasons=append(r.Reasons,fmt.Sprintf("insufficient spam samples: %d < %d",n,c.MinSpamSamples))}
 if n>0 && r.LowerRecall<c.MinRecall {r.Reasons=append(r.Reasons,fmt.Sprintf("lower recall bound %.6f below %.6f",r.LowerRecall,c.MinRecall))}
 r.Passed=len(r.Reasons)==0
 return r
}
// AssessRecallGates fails if either aggregate or any individual tenant fails.
func AssessRecallGates(report Report,c RecallGateConfig)(RecallGateReport,error){
 if err:=c.validate();err!=nil{return RecallGateReport{},err}
 if len(report.ByTenant)==0{return RecallGateReport{},errors.New("report has no tenants")}
 out:=RecallGateReport{Config:c,Overall:recallGate("overall",report.Overall,c)}
 keys:=make([]string,0,len(report.ByTenant))
 for k:=range report.ByTenant {keys=append(keys,k)}
 sort.Strings(keys)
 out.Passed=out.Overall.Passed
 for _,k:=range keys {
  r:=recallGate(k,report.ByTenant[k],c)
  out.Tenants=append(out.Tenants,r)
  if !r.Passed {out.Passed=false}
 }
 return out,nil
}
