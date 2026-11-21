package main

import (
 "fmt"
 "sort"
)

// comparisonGateLimits are acceptance policy, not evidence. Keep the gate
// evaluator pure so CLI and future browser diagnostics cannot disagree.
type comparisonGateLimits struct {
 RequireTenants bool
 MinClean,MinSpam,MaxNewFP,MaxNewFN int
 MaxFPR,MaxFNR,MaxFPRUpper,MaxFNRUpper float64
 MinTenantClean,MinTenantSpam,MaxTenantNewFP,MaxTenantNewFN int
 MaxTenantFPR,MaxTenantFNR,MaxTenantFPRUpper,MaxTenantFNRUpper float64
}

func assessComparisonGates(r comparisonReport,l comparisonGateLimits) []string {
 failures:=make([]string,0)
 add:=func(code string){failures=append(failures,code)}
 if r.Clean<l.MinClean {add("minimum_clean_samples")}
 if r.Spam<l.MinSpam {add("minimum_spam_samples")}
 if r.NewFalsePositives>l.MaxNewFP {add("new_false_positives")}
 if r.NewFalseNegatives>l.MaxNewFN {add("new_false_negatives")}
 if r.CandidateFalsePositiveRate>l.MaxFPR {add("candidate_false_positive_rate")}
 if r.CandidateFalseNegativeRate>l.MaxFNR {add("candidate_false_negative_rate")}
 if r.CandidateFalsePositiveUpper95>l.MaxFPRUpper {add("candidate_false_positive_upper_95")}
 if r.CandidateFalseNegativeUpper95>l.MaxFNRUpper {add("candidate_false_negative_upper_95")}
 if l.RequireTenants {
  names:=make([]string,0,len(r.ByTenant))
  for name:=range r.ByTenant {names=append(names,name)}
  sort.Strings(names)
  if len(names)==0 {add("tenant_evidence_missing")}
  for _,name:=range names {
   t:=r.ByTenant[name]
   prefix:=fmt.Sprintf("tenant[%q].",name)
   if name=="" {add(prefix+"identity_missing")}
   if t.Clean<l.MinTenantClean {add(prefix+"minimum_clean_samples")}
   if t.Spam<l.MinTenantSpam {add(prefix+"minimum_spam_samples")}
   if l.MaxTenantNewFP>=0&&t.NewFalsePositives>l.MaxTenantNewFP {add(prefix+"new_false_positives")}
   if l.MaxTenantNewFN>=0&&t.NewFalseNegatives>l.MaxTenantNewFN {add(prefix+"new_false_negatives")}
   if t.CandidateFalsePositiveRate>l.MaxTenantFPR {add(prefix+"candidate_false_positive_rate")}
   if t.CandidateFalseNegativeRate>l.MaxTenantFNR {add(prefix+"candidate_false_negative_rate")}
   if t.CandidateFalsePositiveUpper95>l.MaxTenantFPRUpper {add(prefix+"candidate_false_positive_upper_95")}
   if t.CandidateFalseNegativeUpper95>l.MaxTenantFNRUpper {add(prefix+"candidate_false_negative_upper_95")}
  }
 }
 return failures
}
