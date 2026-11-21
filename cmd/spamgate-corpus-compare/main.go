package main

import (
 "bufio"
 "encoding/json"
 "errors"
 "flag"
 "fmt"
 "io"
 "os"
 "sort"
 "strings"
)

type comparisonSample struct { ID string; Tenant string; Truth string; Score float64 }
type comparisonReport struct {
 GatePassed bool `json:"gate_passed"`
 GateFailures []string `json:"gate_failures"`
 Total int `json:"total"`
 ByTenant map[string]tenantComparison `json:"by_tenant,omitempty"`
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
 NewFalsePositiveIDs []string `json:"new_false_positive_ids"`
 NewFalseNegativeIDs []string `json:"new_false_negative_ids"`
 BaselineFalsePositiveUpper95 float64 `json:"baseline_false_positive_upper_95"`
 CandidateFalsePositiveUpper95 float64 `json:"candidate_false_positive_upper_95"`
 BaselineFalsePositiveRate float64 `json:"baseline_false_positive_rate"`
 CandidateFalsePositiveRate float64 `json:"candidate_false_positive_rate"`
 BaselineFalseNegativeRate float64 `json:"baseline_false_negative_rate"`
 CandidateFalseNegativeRate float64 `json:"candidate_false_negative_rate"`
 BaselineFalseNegativeUpper95 float64 `json:"baseline_false_negative_upper_95"`
 CandidateFalseNegativeUpper95 float64 `json:"candidate_false_negative_upper_95"`
 CleanRegressionPValue float64 `json:"clean_regression_p_value"`
 SpamRegressionPValue float64 `json:"spam_regression_p_value"`
}
func loadCorpus(r io.Reader) (map[string]comparisonSample,error) {
 scan:=bufio.NewScanner(r);scan.Buffer(make([]byte,4096),4*1024*1024)
 samples:=make(map[string]comparisonSample)
 for line:=1;scan.Scan();line++ {
  raw:=strings.TrimSpace(scan.Text());if raw=="" {continue}
  s,err:=decodeSample(raw);if err!=nil{return nil,fmt.Errorf("line %d: %w",line,err)}
  if s.ID=="" || (s.Truth!="clean" && s.Truth!="spam") || !(s.Score>=0 && s.Score<=1) {return nil,fmt.Errorf("line %d: invalid sample",line)}
  if _,exists:=samples[s.ID];exists{return nil,fmt.Errorf("line %d: duplicate id %q",line,s.ID)}
  samples[s.ID]=comparisonSample{ID:s.ID,Tenant:s.Tenant,Truth:s.Truth,Score:s.Score}
 }
 if err:=scan.Err();err!=nil{return nil,err}
 if len(samples)==0{return nil,errors.New("empty corpus")}
 return samples,nil
}
func compareCorpora(baseline,candidate map[string]comparisonSample,threshold float64)(comparisonReport,error){
 r:=comparisonReport{NewFalsePositiveIDs:[]string{},NewFalseNegativeIDs:[]string{},ByTenant:map[string]tenantComparison{}}
 if !(threshold>=0 && threshold<=1){return r,errors.New("threshold must be between 0 and 1")}
 if len(baseline)!=len(candidate){return r,errors.New("corpus sample count differs")}
 for id,b:=range baseline {
  c,ok:=candidate[id];if !ok{return r,fmt.Errorf("candidate missing sample %q",id)}
  if b.Truth!=c.Truth{return r,fmt.Errorf("ground truth changed for %q",id)}
  if b.Tenant!=c.Tenant{return r,fmt.Errorf("tenant changed for %q",id)}
  if !(b.Score>=0&&b.Score<=1&&c.Score>=0&&c.Score<=1){return r,fmt.Errorf("invalid score for %q",id)}
  oldPositive:=b.Score>=threshold;newPositive:=c.Score>=threshold
  updateTenantComparison(r.ByTenant,b.Tenant,b.Truth,oldPositive,newPositive)
  if b.Truth=="clean" {
   r.Clean++
   if oldPositive{r.BaselineFalsePositives++}
   if newPositive{r.CandidateFalsePositives++}
   if !oldPositive&&newPositive{r.NewFalsePositives++;r.NewFalsePositiveIDs=append(r.NewFalsePositiveIDs,id)}
   if oldPositive&&!newPositive{r.FixedFalsePositives++}
  }else if b.Truth=="spam"{
   r.Spam++
   if !oldPositive{r.BaselineFalseNegatives++}
   if !newPositive{r.CandidateFalseNegatives++}
   if oldPositive&&!newPositive{r.NewFalseNegatives++;r.NewFalseNegativeIDs=append(r.NewFalseNegativeIDs,id)}
   if !oldPositive&&newPositive{r.FixedFalseNegatives++}
  }else{return r,fmt.Errorf("invalid truth for %q",id)}
  r.Total++
 }
 if r.Clean==0||r.Spam==0{return r,errors.New("both classes required")}
 r.BaselineFalsePositiveRate=float64(r.BaselineFalsePositives)/float64(r.Clean)
 r.CandidateFalsePositiveRate=float64(r.CandidateFalsePositives)/float64(r.Clean)
 r.BaselineFalsePositiveUpper95=compareWilsonUpper(r.BaselineFalsePositives,r.Clean)
 r.CandidateFalsePositiveUpper95=compareWilsonUpper(r.CandidateFalsePositives,r.Clean)
 r.BaselineFalseNegativeRate=float64(r.BaselineFalseNegatives)/float64(r.Spam)
 r.CandidateFalseNegativeRate=float64(r.CandidateFalseNegatives)/float64(r.Spam)
 r.BaselineFalseNegativeUpper95=compareWilsonUpper(r.BaselineFalseNegatives,r.Spam)
 r.CandidateFalseNegativeUpper95=compareWilsonUpper(r.CandidateFalseNegatives,r.Spam)
 r.CleanRegressionPValue=pairedRegressionP(r.NewFalsePositives,r.FixedFalsePositives)
 r.SpamRegressionPValue=pairedRegressionP(r.NewFalseNegatives,r.FixedFalseNegatives)
 finalizeTenantComparisons(r.ByTenant)
 sort.Strings(r.NewFalsePositiveIDs);sort.Strings(r.NewFalseNegativeIDs)
 return r,nil
}
func compareRun(args []string,stdout,stderr io.Writer)int{
 f:=flag.NewFlagSet("spamgate-corpus-compare",flag.ContinueOnError);f.SetOutput(stderr)
 baselinePath:=f.String("baseline","","baseline JSONL");candidatePath:=f.String("candidate","","candidate JSONL")
 threshold:=f.Float64("threshold",0.5,"classifier threshold")
 maxNewFP:=f.Int("max-new-fp",0,"maximum newly misclassified clean samples")
 maxNewFN:=f.Int("max-new-fn",0,"maximum newly missed spam samples")
 minClean:=f.Int("min-clean",1,"minimum labeled clean samples")
 minSpam:=f.Int("min-spam",1,"minimum labeled spam samples")
 maxCandidateFPR:=f.Float64("max-candidate-fpr",1,"maximum candidate clean false-positive rate")
 maxCandidateFNR:=f.Float64("max-candidate-fnr",1,"maximum candidate spam false-negative rate")
 maxCandidateFNUpper:=f.Float64("max-candidate-fnr-upper-95",1,"maximum candidate Wilson 95 percent upper false-negative bound")
 requireTenants:=f.Bool("require-tenants",false,"require explicit tenant on every sample and enforce tenant-level gates")
 minTenantClean:=f.Int("min-tenant-clean",1,"minimum clean samples per tenant when require-tenants is enabled")
 minTenantSpam:=f.Int("min-tenant-spam",1,"minimum spam samples per tenant when require-tenants is enabled")
 maxTenantNewFP:=f.Int("max-tenant-new-fp",-1,"maximum new false positives per tenant; -1 disables")
 maxTenantNewFN:=f.Int("max-tenant-new-fn",-1,"maximum new false negatives per tenant; -1 disables")
 maxTenantFPR:=f.Float64("max-tenant-fpr",1,"maximum false-positive rate per tenant")
 maxTenantFNR:=f.Float64("max-tenant-fnr",1,"maximum false-negative rate per tenant")
 maxTenantFPRUpper:=f.Float64("max-tenant-fpr-upper-95",1,"maximum Wilson upper false-positive bound per tenant")
 maxTenantFNRUpper:=f.Float64("max-tenant-fnr-upper-95",1,"maximum Wilson upper false-negative bound per tenant")
 maxCandidateUpper:=f.Float64("max-candidate-fpr-upper-95",1,"maximum candidate Wilson 95 percent upper false-positive bound")
 if err:=f.Parse(args);err!=nil{return 2}
 tenantGateSupplied:=false
 f.Visit(func(option *flag.Flag){switch option.Name {case "min-tenant-clean","min-tenant-spam","max-tenant-fpr","max-tenant-fnr","max-tenant-fpr-upper-95","max-tenant-fnr-upper-95","max-tenant-new-fp","max-tenant-new-fn":tenantGateSupplied=true}})
 if tenantGateSupplied && !*requireTenants {fmt.Fprintln(stderr,"tenant gates require -require-tenants");return 2}
 if *maxTenantNewFP < -1 || *maxTenantNewFN < -1 || *minTenantClean<1||*minTenantSpam<1||!validRate(*maxTenantFPR)||!validRate(*maxTenantFNR)||!validRate(*maxTenantFPRUpper)||!validRate(*maxTenantFNRUpper){fmt.Fprintln(stderr,"invalid tenant gate arguments");return 2}
 if *baselinePath==""||*candidatePath==""||*baselinePath==*candidatePath||f.NArg()!=0||*maxNewFP<0||*maxNewFN<0||*minClean<1||*minSpam<1||!(*maxCandidateFPR>=0&&*maxCandidateFPR<=1)||!(*maxCandidateUpper>=0&&*maxCandidateUpper<=1)||!(*maxCandidateFNR>=0&&*maxCandidateFNR<=1)||!(*maxCandidateFNUpper>=0&&*maxCandidateFNUpper<=1)||!(*threshold>=0&&*threshold<=1){fmt.Fprintln(stderr,"invalid arguments");return 2}
 bf,err:=os.Open(*baselinePath);if err!=nil{fmt.Fprintln(stderr,err);return 2};defer bf.Close()
 cf,err:=os.Open(*candidatePath);if err!=nil{fmt.Fprintln(stderr,err);return 2};defer cf.Close()
 b,err:=loadCorpus(bf);if err!=nil{fmt.Fprintln(stderr,"baseline:",err);return 2}
 c,err:=loadCorpus(cf);if err!=nil{fmt.Fprintln(stderr,"candidate:",err);return 2}
 report,err:=compareCorpora(b,c,*threshold);if err!=nil{fmt.Fprintln(stderr,err);return 2}
 report.GateFailures=assessComparisonGates(report,comparisonGateLimits{
  RequireTenants:*requireTenants,MinClean:*minClean,MinSpam:*minSpam,
  MaxNewFP:*maxNewFP,MaxNewFN:*maxNewFN,
  MaxFPR:*maxCandidateFPR,MaxFNR:*maxCandidateFNR,
  MaxFPRUpper:*maxCandidateUpper,MaxFNRUpper:*maxCandidateFNUpper,
  MinTenantClean:*minTenantClean,MinTenantSpam:*minTenantSpam,
  MaxTenantNewFP:*maxTenantNewFP,MaxTenantNewFN:*maxTenantNewFN,
  MaxTenantFPR:*maxTenantFPR,MaxTenantFNR:*maxTenantFNR,
  MaxTenantFPRUpper:*maxTenantFPRUpper,MaxTenantFNRUpper:*maxTenantFNRUpper,
 })
 report.GatePassed=len(report.GateFailures)==0
 if err:=json.NewEncoder(stdout).Encode(report);err!=nil{fmt.Fprintln(stderr,err);return 2}
 if !report.GatePassed {fmt.Fprintln(stderr,"classifier regression gate failed:",strings.Join(report.GateFailures,", "));return 1}
 return 0
}
func main(){os.Exit(compareRun(os.Args[1:],os.Stdout,os.Stderr))}
