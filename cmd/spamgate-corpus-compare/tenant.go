package main

import "math"

// tenantComparison retains paired outcomes separately for every tenant.
// An empty tenant is a legacy unscoped cohort and is refused by -require-tenants.
type tenantComparison struct {
 Clean int `json:"clean"`
 Spam int `json:"spam"`
 BaselineFalsePositives int `json:"baseline_false_positives"`
 CandidateFalsePositives int `json:"candidate_false_positives"`
 NewFalsePositives int `json:"new_false_positives"`
 FixedFalsePositives int `json:"fixed_false_positives"`
 BaselineFalseNegatives int `json:"baseline_false_negatives"`
 CandidateFalseNegatives int `json:"candidate_false_negatives"`
 NewFalseNegatives int `json:"new_false_negatives"`
 FixedFalseNegatives int `json:"fixed_false_negatives"`
 CandidateFalsePositiveRate float64 `json:"candidate_false_positive_rate"`
 CandidateFalseNegativeRate float64 `json:"candidate_false_negative_rate"`
 CandidateFalsePositiveUpper95 float64 `json:"candidate_false_positive_upper_95"`
 CandidateFalseNegativeUpper95 float64 `json:"candidate_false_negative_upper_95"`
 CleanRegressionPValue float64 `json:"clean_regression_p_value"`
 SpamRegressionPValue float64 `json:"spam_regression_p_value"`
}
func updateTenantComparison(by map[string]tenantComparison,tenant,truth string,oldPositive,newPositive bool) {
 t:=by[tenant]
 if truth=="clean" {
  t.Clean++
  if oldPositive {t.BaselineFalsePositives++}
  if newPositive {t.CandidateFalsePositives++}
  if !oldPositive&&newPositive {t.NewFalsePositives++}
  if oldPositive&&!newPositive {t.FixedFalsePositives++}
 } else if truth=="spam" {
  t.Spam++
  if !oldPositive {t.BaselineFalseNegatives++}
  if !newPositive {t.CandidateFalseNegatives++}
  if oldPositive&&!newPositive {t.NewFalseNegatives++}
  if !oldPositive&&newPositive {t.FixedFalseNegatives++}
 }
 by[tenant]=t
}
func finalizeTenantComparisons(by map[string]tenantComparison) {
 for name,t:=range by {
  if t.Clean>0 {
   t.CandidateFalsePositiveRate=float64(t.CandidateFalsePositives)/float64(t.Clean)
   t.CandidateFalsePositiveUpper95=compareWilsonUpper(t.CandidateFalsePositives,t.Clean)
  }
  if t.Spam>0 {
   t.CandidateFalseNegativeRate=float64(t.CandidateFalseNegatives)/float64(t.Spam)
   t.CandidateFalseNegativeUpper95=compareWilsonUpper(t.CandidateFalseNegatives,t.Spam)
  }
  t.CleanRegressionPValue=pairedRegressionP(t.NewFalsePositives,t.FixedFalsePositives)
  t.SpamRegressionPValue=pairedRegressionP(t.NewFalseNegatives,t.FixedFalseNegatives)
  by[name]=t
 }
}
func validRate(v float64) bool {return !math.IsNaN(v)&&!math.IsInf(v,0)&&v>=0&&v<=1}
func tenantGatesPass(by map[string]tenantComparison,maxFPR,maxFNR,maxFPRUpper,maxFNRUpper float64) bool {
 if len(by)==0 {return false}
 for name,t:=range by {
  if name==""||t.Clean==0||t.Spam==0||t.CandidateFalsePositiveRate>maxFPR||t.CandidateFalseNegativeRate>maxFNR||t.CandidateFalsePositiveUpper95>maxFPRUpper||t.CandidateFalseNegativeUpper95>maxFNRUpper {return false}
 }
 return true
}
