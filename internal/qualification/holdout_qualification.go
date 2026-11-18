package qualification

import (
 "errors"
 "fmt"
 "sort"
)

// HoldoutQualification is an offline, non-mutating evaluation of a threshold
// selected using tuning samples against a separate, ID-disjoint holdout set.
// Passing does not establish label independence or production readiness.
type HoldoutQualification struct {
 Tuning ThresholdSelection `json:"tuning"`
 Holdout *ThresholdCandidate `json:"holdout,omitempty"`
 MissingTenants []string `json:"missing_tenants,omitempty"`
 NewTenants []string `json:"new_tenants,omitempty"`
 Passed bool `json:"passed"`
}

// QualifyIndependentHoldout selects a threshold ONLY from tuning samples,
// then evaluates that frozen threshold on holdout samples. It refuses to
// qualify when either corpus is empty, IDs overlap, tenant populations differ,
// or any statistical gate fails on the holdout.
func QualifyIndependentHoldout(tuning, holdout []Sample, thresholds []float64, fp GateConfig, precision PrecisionGateConfig, recall RecallGateConfig) (HoldoutQualification, error) {
 if len(tuning)==0 || len(holdout)==0 {
  return HoldoutQualification{}, errors.New("tuning and holdout corpora must both be nonempty")
 }
 if err:=ValidateIndependentHoldout(tuning,holdout);err!=nil {
  return HoldoutQualification{},fmt.Errorf("holdout independence: %w",err)
 }
 selected,err:=SelectQualifiedThreshold(tuning,thresholds,fp,precision,recall)
 if err!=nil{return HoldoutQualification{},err}
 out:=HoldoutQualification{Tuning:selected}
 if selected.Selected==nil{return out,nil}
 tuningTenants:=make(map[string]struct{})
 holdoutTenants:=make(map[string]struct{})
 for _,s:=range tuning{tuningTenants[s.Tenant]=struct{}{}}
 for _,s:=range holdout{holdoutTenants[s.Tenant]=struct{}{}}
 for tenant:=range tuningTenants {
  if _,ok:=holdoutTenants[tenant];!ok{out.MissingTenants=append(out.MissingTenants,tenant)}
 }
 for tenant:=range holdoutTenants {
  if _,ok:=tuningTenants[tenant];!ok{out.NewTenants=append(out.NewTenants,tenant)}
 }
 sort.Strings(out.MissingTenants)
 sort.Strings(out.NewTenants)
 // The frozen threshold is the only candidate evaluated on the holdout.
 verified,err:=SelectQualifiedThreshold(holdout,[]float64{selected.Selected.Threshold},fp,precision,recall)
 if err!=nil{return HoldoutQualification{},err}
 if len(verified.Candidates)!=1{return HoldoutQualification{},errors.New("expected one holdout candidate")}
 candidate:=verified.Candidates[0]
 out.Holdout=&candidate
 out.Passed=candidate.Passed && len(out.MissingTenants)==0 && len(out.NewTenants)==0
 return out,nil
}
