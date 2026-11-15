package main

import "sort"

// Cohorts are deliberately fixed, content-free categories. No arbitrary
// tenant names, email addresses, domains, IDs or message metadata are emitted.
func validEvaluationCohort(s string)bool{
 switch s{
 case "direct","forwarded","attachment","internationalized","bulk","other":
  return true
 }
 return false
}

func addEvaluationOutcome(c *counts,label string,flagged bool){
 if label=="ham"{
  c.Ham++
  if flagged{c.FP++}else{c.TN++}
 }else{
  c.Spam++
  if flagged{c.TP++}else{c.FN++}
 }
}

type cohortResult struct{
 Name string `json:"name"`
 Counts counts `json:"counts"`
 FalsePositiveUpper95 float64 `json:"false_positive_upper_95"`
 RecallLower95 float64 `json:"recall_lower_95"`
 Precision float64 `json:"precision"`
 PrecisionLower95 float64 `json:"precision_lower_95"`
 MinimumPrecisionLower95 float64 `json:"minimum_precision_lower_95"`
 RejectFalsePositiveUpper95 float64 `json:"reject_false_positive_upper_95"`
 MaximumRejectFalsePositiveUpper95 float64 `json:"maximum_reject_false_positive_upper_95"`
 RejectGatePassed bool `json:"reject_gate_passed"`
 DisruptiveFalsePositiveUpper95 float64 `json:"disruptive_false_positive_upper_95"`
 MaximumDisruptiveFalsePositiveUpper95 float64 `json:"maximum_disruptive_false_positive_upper_95"`
 DisruptiveGatePassed bool `json:"disruptive_gate_passed"`
 GatePassed bool `json:"gate_passed"`
}

// Global results can hide catastrophic performance on a minority mail path.
// When the cohort gate is requested, all records must be classified, at least
// two categories must be represented, and every category must meet both sample
// size and Wilson confidence thresholds. These are still corpus-only metrics.
func evaluateCohorts(cohorts map[string]counts,unspecified,minHam,minSpam int,maxFPR,minRecall float64)([]cohortResult,bool){
 return evaluateCohortsWithPrecision(cohorts,unspecified,minHam,minSpam,maxFPR,minRecall,0)
}

func evaluateCohortsWithPrecision(cohorts map[string]counts,unspecified,minHam,minSpam int,maxFPR,minRecall,minPrecision float64)([]cohortResult,bool){
 return evaluateCohortsWithRejectPrecision(cohorts,unspecified,minHam,minSpam,maxFPR,minRecall,minPrecision,1)
}

// Evaluate outright ham rejection independently in each cohort. A global
// rejection bound can conceal unsafe rejection of a minority mail path.
func evaluateCohortsWithRejectPrecision(cohorts map[string]counts,unspecified,minHam,minSpam int,maxFPR,minRecall,minPrecision,maxRejectFPR float64)([]cohortResult,bool){
 return evaluateCohortsWithDisruptivePrecision(cohorts,unspecified,minHam,minSpam,maxFPR,minRecall,minPrecision,maxRejectFPR,1)
}

func evaluateCohortsWithDisruptivePrecision(cohorts map[string]counts,unspecified,minHam,minSpam int,maxFPR,minRecall,minPrecision,maxRejectFPR,maxDisruptiveFPR float64)([]cohortResult,bool){
 keys:=make([]string,0,len(cohorts))
 for name:=range cohorts{keys=append(keys,name)}
 sort.Strings(keys)
 results:=make([]cohortResult,0,len(keys))
 passed:=unspecified==0&&len(keys)>=2
 for _,name:=range keys{
  r:=evaluateWithPrecision(cohorts[name],minHam,minSpam,maxFPR,minRecall,minPrecision)
  rejectUpper:=wilson(cohorts[name].RejectedHam,cohorts[name].Ham,true)
  rejectPassed:=cohorts[name].Ham>0&&rejectUpper<=maxRejectFPR
  disruptiveUpper:=wilson(cohorts[name].RejectedHam+cohorts[name].QuarantinedHam+cohorts[name].SoftRejectedHam,cohorts[name].Ham,true)
  disruptivePassed:=cohorts[name].Ham>0&&disruptiveUpper<=maxDisruptiveFPR
  results=append(results,cohortResult{
   Name:name,Counts:r.Counts,FalsePositiveUpper95:r.FalsePositiveUpper95,
   RecallLower95:r.RecallLower95,Precision:r.Precision,
   PrecisionLower95:r.PrecisionLower95,MinimumPrecisionLower95:minPrecision,
   RejectFalsePositiveUpper95:rejectUpper,MaximumRejectFalsePositiveUpper95:maxRejectFPR,
   RejectGatePassed:rejectPassed,DisruptiveFalsePositiveUpper95:disruptiveUpper,
   MaximumDisruptiveFalsePositiveUpper95:maxDisruptiveFPR,DisruptiveGatePassed:disruptivePassed,
   GatePassed:r.GatePassed&&rejectPassed&&disruptivePassed,
  })
  if !r.GatePassed||!rejectPassed||!disruptivePassed{passed=false}
 }
 return results,passed
}
