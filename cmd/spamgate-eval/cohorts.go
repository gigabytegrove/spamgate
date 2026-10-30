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
 GatePassed bool `json:"gate_passed"`
}

// Global results can hide catastrophic performance on a minority mail path.
// When the cohort gate is requested, all records must be classified, at least
// two categories must be represented, and every category must meet both sample
// size and Wilson confidence thresholds. These are still corpus-only metrics.
func evaluateCohorts(cohorts map[string]counts,unspecified,minHam,minSpam int,maxFPR,minRecall float64)([]cohortResult,bool){
 keys:=make([]string,0,len(cohorts))
 for name:=range cohorts{keys=append(keys,name)}
 sort.Strings(keys)
 results:=make([]cohortResult,0,len(keys))
 passed:=unspecified==0&&len(keys)>=2
 for _,name:=range keys{
  r:=evaluate(cohorts[name],minHam,minSpam,maxFPR,minRecall)
  results=append(results,cohortResult{
   Name:name,Counts:r.Counts,FalsePositiveUpper95:r.FalsePositiveUpper95,
   RecallLower95:r.RecallLower95,GatePassed:r.GatePassed,
  })
  if !r.GatePassed{passed=false}
 }
 return results,passed
}
