package qualification

import (
 "errors"
 "fmt"
 "math"
 "sort"
)

// PrecisionGateConfig bounds the fraction of false alarms among predicted spam.
// Precision cannot replace the clean-mail false-positive-rate gate.
type PrecisionGateConfig struct {
 MinPrecision float64 `json:"min_precision"`
 MinPredictedSpam int `json:"min_predicted_spam"`
 ZScore float64 `json:"z_score"`
}
type PrecisionGateResult struct {
 Tenant string `json:"tenant"`
 PredictedSpam int `json:"predicted_spam"`
 TruePositives int `json:"true_positives"`
 FalsePositives int `json:"false_positives"`
 ObservedPrecision float64 `json:"observed_precision"`
 LowerPrecision float64 `json:"lower_precision"`
 Passed bool `json:"passed"`
 Reasons []string `json:"reasons,omitempty"`
}
type PrecisionGateReport struct {
 Config PrecisionGateConfig `json:"config"`
 Overall PrecisionGateResult `json:"overall"`
 Tenants []PrecisionGateResult `json:"tenants"`
 Passed bool `json:"passed"`
}
func (c PrecisionGateConfig) validate() error {
 if math.IsNaN(c.MinPrecision)||math.IsInf(c.MinPrecision,0)||c.MinPrecision<0||c.MinPrecision>1{return errors.New("minimum precision must be finite and between 0 and 1")}
 if c.MinPredictedSpam<1{return errors.New("minimum predicted spam samples must be positive")}
 if math.IsNaN(c.ZScore)||math.IsInf(c.ZScore,0)||c.ZScore<=0||c.ZScore>10{return errors.New("z score must be finite and in (0,10]")}
 return nil
}
func precisionGate(tenant string,m Metrics,c PrecisionGateConfig) PrecisionGateResult {
 n:=m.TruePositive+m.FalsePositive
 r:=PrecisionGateResult{Tenant:tenant,PredictedSpam:n,TruePositives:m.TruePositive,FalsePositives:m.FalsePositive,ObservedPrecision:m.Precision}
 if n>0 {r.LowerPrecision,_=WilsonLower(m.TruePositive,n,c.ZScore)}
 if n<c.MinPredictedSpam {r.Reasons=append(r.Reasons,fmt.Sprintf("insufficient predicted spam samples: %d < %d",n,c.MinPredictedSpam))}
 if n>0 && r.LowerPrecision<c.MinPrecision {r.Reasons=append(r.Reasons,fmt.Sprintf("lower precision bound %.6f below %.6f",r.LowerPrecision,c.MinPrecision))}
 r.Passed=len(r.Reasons)==0
 return r
}
// AssessPrecisionGates requires both the aggregate and every tenant to pass.
func AssessPrecisionGates(report Report,c PrecisionGateConfig)(PrecisionGateReport,error){
 if err:=c.validate();err!=nil{return PrecisionGateReport{},err}
 if len(report.ByTenant)==0{return PrecisionGateReport{},errors.New("report has no tenants")}
 out:=PrecisionGateReport{Config:c,Overall:precisionGate("overall",report.Overall,c)}
 keys:=make([]string,0,len(report.ByTenant))
 for k:=range report.ByTenant{keys=append(keys,k)}
 sort.Strings(keys)
 out.Passed=out.Overall.Passed
 for _,k:=range keys{
  r:=precisionGate(k,report.ByTenant[k],c)
  out.Tenants=append(out.Tenants,r)
  if !r.Passed{out.Passed=false}
 }
 return out,nil
}
