package qualification

import (
 "errors"
 "math"
)

// ThresholdCandidate contains independent, tenant-aware false-positive,
// precision and recall evidence for a proposed offline threshold.
type ThresholdCandidate struct {
 Threshold float64 `json:"threshold"`
 Metrics Report `json:"metrics"`
 FalsePositive GateReport `json:"false_positive"`
 Precision PrecisionGateReport `json:"precision"`
 Recall RecallGateReport `json:"recall"`
 Passed bool `json:"passed"`
}

// ThresholdSelection is an advisory report, never an instruction to mutate
// live classifier policy. No passing candidate means Selected is nil.
type ThresholdSelection struct {
 Candidates []ThresholdCandidate `json:"candidates"`
 Selected *ThresholdCandidate `json:"selected,omitempty"`
}

// SelectQualifiedThreshold evaluates every candidate against all three
// independent statistical gates, including every tenant. Among passing
// candidates it maximizes observed recall, then minimizes observed false
// positives, then chooses the higher threshold. This deterministic ranking
// is descriptive only: threshold tuning on the same corpus is not independent
// validation and must not be used as production acceptance evidence.
func SelectQualifiedThreshold(samples []Sample, thresholds []float64, fp GateConfig, precision PrecisionGateConfig, recall RecallGateConfig) (ThresholdSelection, error) {
 if err:=fp.validate();err!=nil{return ThresholdSelection{},err}
 if err:=precision.validate();err!=nil{return ThresholdSelection{},err}
 if err:=recall.validate();err!=nil{return ThresholdSelection{},err}
 reports,err:=Sweep(samples,thresholds)
 if err!=nil{return ThresholdSelection{},err}
 out:=ThresholdSelection{Candidates:make([]ThresholdCandidate,0,len(reports))}
 best:=-1
 for _,r:=range reports {
  f,e:=AssessGates(r,fp);if e!=nil{return ThresholdSelection{},e}
  p,e:=AssessPrecisionGates(r,precision);if e!=nil{return ThresholdSelection{},e}
  q,e:=AssessRecallGates(r,recall);if e!=nil{return ThresholdSelection{},e}
  c:=ThresholdCandidate{Threshold:r.Threshold,Metrics:r,FalsePositive:f,Precision:p,Recall:q,Passed:f.Passed&&p.Passed&&q.Passed}
  out.Candidates=append(out.Candidates,c)
  i:=len(out.Candidates)-1
  if !c.Passed {continue}
  if best<0 || betterThreshold(c,out.Candidates[best]) {best=i}
 }
 if best>=0 {
  chosen:=out.Candidates[best]
  out.Selected=&chosen
 }
 return out,nil
}

func betterThreshold(a,b ThresholdCandidate) bool {
 ar,br:=a.Metrics.Overall.Recall,b.Metrics.Overall.Recall
 if ar!=br{return ar>br}
 af,bf:=a.Metrics.Overall.FalsePositive,b.Metrics.Overall.FalsePositive
 if af!=bf{return af<bf}
 // Explicitly reject non-finite scores rather than allowing undefined ordering.
 return !math.IsNaN(a.Threshold) && a.Threshold>b.Threshold
}

// ValidateIndependentHoldout ensures a separately supplied evaluation corpus
// does not reuse sample IDs from the tuning corpus, including across tenants.
// It cannot establish label quality, independence of message families, or
// representativeness; those remain operational acceptance requirements.
func ValidateIndependentHoldout(tuning,holdout []Sample) error {
 if err:=Validate(tuning,0);err!=nil{return err}
 if err:=Validate(holdout,0);err!=nil{return err}
 seen:=make(map[string]struct{},len(tuning))
 for _,s:=range tuning {seen[s.ID]=struct{}{}}
 for _,s:=range holdout {
  if _,ok:=seen[s.ID];ok{return errors.New("holdout reuses tuning sample ID")}
 }
 return nil
}
