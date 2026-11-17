// spamgate-classifier-eval evaluates labeled offline corpora without altering live mail.
package main

import (
 "bytes"
 "encoding/json"
 "math"
 "errors"
 "flag"
 "fmt"
 "io"
 "os"
 "strings"
 "sort"

 "github.com/gigabytegrove/spamgate/internal/qualification"
)
func run(args []string,in io.Reader,out io.Writer) error {
 flags:=flag.NewFlagSet("spamgate-classifier-eval",flag.ContinueOnError)
 flags.SetOutput(io.Discard)
 expectedTenants:=flags.String("expected-tenants","","required comma-separated tenant inventory")
 auditCorpus:=flags.Bool("audit-corpus",false,"include deterministic per-tenant corpus composition audit")
 boundaryMargin:=flags.Float64("audit-boundary-margin",-1,"optional nonnegative score distance for per-tenant threshold-boundary audit")
 stabilityMargin:=flags.Float64("stability-margin",-1,"optional nonnegative threshold perturbation for per-tenant sensitivity audit")
 maxStabilityFlips:=flags.Float64("max-stability-flips",-1,"optional maximum per-tenant fraction of decisions flipped under threshold perturbation, 0..1; requires stability-margin")
 threshold:=flags.Float64("threshold",5,"score at or above this value is classified as spam")
 maxFP:=flags.Float64("max-fp-upper",-1,"optional one-sided Wilson false-positive upper bound, 0..1")
 minPrecision:=flags.Float64("min-precision",-1,"optional one-sided Wilson precision lower bound, 0..1")
 minPredicted:=flags.Int("min-predicted-spam",100,"minimum predicted spam samples per tenant when precision gating")
 minRecall:=flags.Float64("min-recall",-1,"optional one-sided Wilson recall lower bound, 0..1")
 minSpam:=flags.Int("min-spam",100,"minimum spam samples per tenant when recall gating")
 minClean:=flags.Int("min-clean",100,"minimum clean samples per tenant when gating")
 zScore:=flags.Float64("z-score",1.6448536269514722,"one-sided confidence z score when gating")
 if err:=flags.Parse(args);err!=nil{return err}
 if flags.NArg()!=0{return errors.New("unexpected positional arguments")}
 if err:=validateTenantInventoryOption(flags,*expectedTenants);err!=nil{return err}
 // Reject malformed or disabled acceptance settings before reading any corpus.
 if err:=validateOptions(flags,*threshold,*boundaryMargin,*maxFP,*minRecall,*minPrecision,*minClean,*minSpam,*minPredicted,*zScore);err!=nil{return err}
 if err:=validateStabilityOptions(flags,*stabilityMargin,*maxStabilityFlips);err!=nil{return err}
 const maxCorpusBytes = 32 << 20
 payload,err:=io.ReadAll(io.LimitReader(in,maxCorpusBytes+1))
 if err!=nil{return fmt.Errorf("read corpus: %w",err)}
 if len(payload)>maxCorpusBytes{return fmt.Errorf("corpus exceeds %d byte limit",maxCorpusBytes)}
 if err:=rejectDuplicateJSONKeys(payload);err!=nil{return fmt.Errorf("corpus integrity: %w",err)}
 if err:=validateCorpusSchema(payload);err!=nil{return fmt.Errorf("corpus schema: %w",err)}
 dec:=json.NewDecoder(bytes.NewReader(payload))
 dec.DisallowUnknownFields()
 var samples []qualification.Sample
 if err:=dec.Decode(&samples);err!=nil{return fmt.Errorf("decode corpus: %w",err)}
 var extra any
 if err:=dec.Decode(&extra);err!=io.EOF {
  if err==nil{return errors.New("trailing JSON content")}
  return fmt.Errorf("trailing input: %w",err)
 }
 if err:=checkTenantCoverage(samples,*expectedTenants);err!=nil{return err}
 if err:=checkTenantSampleMinimums(samples,*expectedTenants,*minClean,*minSpam,flags);err!=nil{return err}
 report,err:=qualification.Evaluate(samples,*threshold);if err!=nil{return err}
 enc:=json.NewEncoder(out);enc.SetIndent("","  ")
 if *maxFP>=0 || *minRecall>=0 || *minPrecision>=0 || *auditCorpus || *boundaryMargin>=0 || *stabilityMargin>=0 {
  result:=struct{Evaluation qualification.Report `json:"evaluation"`; Gates *qualification.GateReport `json:"gates,omitempty"`; RecallGates *qualification.RecallGateReport `json:"recall_gates,omitempty"`; PrecisionGates *qualification.PrecisionGateReport `json:"precision_gates,omitempty"`; CorpusAudit *qualification.CorpusAudit `json:"corpus_audit,omitempty"`; BoundaryAudit *qualification.BoundaryAudit `json:"boundary_audit,omitempty"`; StabilityAudit *qualification.StabilityAudit `json:"stability_audit,omitempty"`}{Evaluation:report}
  if *auditCorpus { audit,err:=qualification.AuditCorpus(samples);if err!=nil{return err};result.CorpusAudit=&audit }
  if *boundaryMargin>=0 { audit,err:=qualification.AuditBoundary(samples,*threshold,*boundaryMargin);if err!=nil{return err};result.BoundaryAudit=&audit }
  passed:=true
  if *stabilityMargin>=0 {
   audit,err:=qualification.AuditThresholdStability(samples,*threshold,*stabilityMargin,*maxStabilityFlips)
   if err!=nil{return err}
   result.StabilityAudit=&audit
   if !audit.Passed{passed=false}
  }
  if *maxFP>=0 {
  gates,err:=qualification.AssessGates(report,qualification.GateConfig{MaxFalsePositiveRate:*maxFP,MinCleanSamples:*minClean,ZScore:*zScore});if err!=nil{return err}
  result.Gates=&gates
  if !gates.Passed {passed=false}
  }
  if *minRecall>=0 {
   recall,err:=qualification.AssessRecallGates(report,qualification.RecallGateConfig{MinRecall:*minRecall,MinSpamSamples:*minSpam,ZScore:*zScore});if err!=nil{return err}
   result.RecallGates=&recall
   if !recall.Passed {passed=false}
  }
  if *minPrecision>=0 {
   precision,err:=qualification.AssessPrecisionGates(report,qualification.PrecisionGateConfig{MinPrecision:*minPrecision,MinPredictedSpam:*minPredicted,ZScore:*zScore});if err!=nil{return err}
   result.PrecisionGates=&precision
   if !precision.Passed {passed=false}
  }
  if err:=enc.Encode(result);err!=nil{return err}
  if !passed{return errors.New("classifier qualification gates failed")}
  return nil
 }
 return enc.Encode(report)
}
// validateOptions is intentionally strict: an explicitly supplied invalid gate
// must never silently turn qualification off (for example -min-recall=-0.1).
func validateOptions(flags *flag.FlagSet,threshold,margin,maxFP,minRecall,minPrecision float64,minClean,minSpam,minPredicted int,z float64) error {
 finite:=func(v float64) bool{return !math.IsNaN(v)&&!math.IsInf(v,0)}
 if !finite(threshold){return errors.New("threshold must be finite")}
 supplied:=map[string]bool{}
 flags.Visit(func(f *flag.Flag){supplied[f.Name]=true})
 for _,opt:=range []struct{name string;value float64}{
  {"audit-boundary-margin",margin},{"max-fp-upper",maxFP},
  {"min-recall",minRecall},{"min-precision",minPrecision},
 }{
  if !finite(opt.value){return fmt.Errorf("%s must be finite",opt.name)}
  if supplied[opt.name]{
   if opt.name=="audit-boundary-margin" {
    if opt.value<0{return errors.New("audit-boundary-margin must be nonnegative")}
   }else if opt.value<0||opt.value>1{return fmt.Errorf("%s must be between 0 and 1",opt.name)}
  }
 }
 if supplied["min-clean"]&&minClean<1{return errors.New("min-clean must be positive")}
 if supplied["min-spam"]&&minSpam<1{return errors.New("min-spam must be positive")}
 if supplied["min-predicted-spam"]&&minPredicted<1{return errors.New("min-predicted-spam must be positive")}
 if supplied["z-score"]&&(!finite(z)||z<=0||z>10){return errors.New("z-score must be finite and in (0,10]")}
 return nil
}
func main(){
 if err:=run(os.Args[1:],os.Stdin,os.Stdout);err!=nil{
  fmt.Fprintln(os.Stderr,"classifier evaluation:",strings.TrimSpace(err.Error()))
  os.Exit(1)
 }
}

func checkTenantCoverage(samples []qualification.Sample, spec string) error {
 if spec=="" {return nil}
 expected:=map[string]bool{}
 for _,part:=range strings.Split(spec,",") {name:=strings.TrimSpace(part);if name=="" {return errors.New("empty expected tenant")};if expected[name] {return fmt.Errorf("duplicate expected tenant %q",name)};expected[name]=true}
 actual:=map[string]bool{}
 for _,sample:=range samples {actual[sample.Tenant]=true}
 missing,extra:=[]string{},[]string{}
 for name:=range expected {if !actual[name] {missing=append(missing,name)}}
 for name:=range actual {if !expected[name] {extra=append(extra,name)}}
 sort.Strings(missing);sort.Strings(extra)
 if len(missing)>0||len(extra)>0 {return fmt.Errorf("tenant coverage mismatch: missing=%q unexpected=%q",missing,extra)}
 return nil
}

// checkTenantSampleMinimums prevents a nominally present tenant from passing
// qualification with too few labeled clean or spam messages. It is activated
// only for explicit expected-tenant qualification with at least one classifier
// gate; exploratory evaluations retain their existing behavior.
func checkTenantSampleMinimums(samples []qualification.Sample, spec string, minClean, minSpam int, flags *flag.FlagSet) error {
 if spec=="" {return nil}
 enabled:=false
 flags.Visit(func(f *flag.Flag){if f.Name=="max-fp-upper"||f.Name=="min-recall"||f.Name=="min-precision"{enabled=true}})
 if !enabled{return nil}
 type counts struct{clean,spam int}
 byTenant:=map[string]counts{}
 for _,sample:=range samples {
  c:=byTenant[sample.Tenant]
  if sample.Spam {c.spam++} else {c.clean++}
  byTenant[sample.Tenant]=c
 }
 names:=make([]string,0,len(byTenant))
 for name:=range byTenant {names=append(names,name)}
 sort.Strings(names)
 for _,name:=range names {
  c:=byTenant[name]
  if c.clean<minClean || c.spam<minSpam {
   return fmt.Errorf("tenant %q insufficient labeled corpus: clean=%d (minimum %d), spam=%d (minimum %d)",name,c.clean,minClean,c.spam,minSpam)
  }
 }
 return nil
}


// validateTenantInventoryOption distinguishes an omitted optional inventory
// from an explicitly empty one. An empty value must not disable tenant gates.
func validateTenantInventoryOption(flags *flag.FlagSet, spec string) error {
 supplied:=false
 flags.Visit(func(f *flag.Flag){if f.Name=="expected-tenants"{supplied=true}})
 if !supplied{return nil}
 if strings.TrimSpace(spec)=="" {return errors.New("expected-tenants must not be empty when supplied")}
 for _,part:=range strings.Split(spec,",") {
  if strings.TrimSpace(part)=="" {return errors.New("expected-tenants contains an empty tenant")}
  if part!=strings.TrimSpace(part) {return errors.New("expected-tenants entries must not contain surrounding whitespace")}
 }
 return nil
}

// validateStabilityOptions makes a sensitivity gate impossible to silently
// disable through negative sentinels, omitted margins or non-finite values.
func validateStabilityOptions(flags *flag.FlagSet, margin,maxFlips float64) error {
 supplied:=map[string]bool{}
 flags.Visit(func(f *flag.Flag){supplied[f.Name]=true})
 if supplied["stability-margin"] {
  if math.IsNaN(margin)||math.IsInf(margin,0)||margin<0{return errors.New("stability-margin must be finite and nonnegative")}
 }
 if supplied["max-stability-flips"] {
  if math.IsNaN(maxFlips)||math.IsInf(maxFlips,0)||maxFlips<0||maxFlips>1{return errors.New("max-stability-flips must be between 0 and 1")}
  if !supplied["stability-margin"]{return errors.New("max-stability-flips requires stability-margin")}
 }
 return nil
}
