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

 "github.com/gigabytegrove/spamgate/internal/qualification"
)
func run(args []string,in io.Reader,out io.Writer) error {
 flags:=flag.NewFlagSet("spamgate-classifier-eval",flag.ContinueOnError)
 flags.SetOutput(io.Discard)
 auditCorpus:=flags.Bool("audit-corpus",false,"include deterministic per-tenant corpus composition audit")
 boundaryMargin:=flags.Float64("audit-boundary-margin",-1,"optional nonnegative score distance for per-tenant threshold-boundary audit")
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
 // Reject malformed or disabled acceptance settings before reading any corpus.
 if err:=validateOptions(flags,*threshold,*boundaryMargin,*maxFP,*minRecall,*minPrecision,*minClean,*minSpam,*minPredicted,*zScore);err!=nil{return err}
 const maxCorpusBytes = 32 << 20
 payload,err:=io.ReadAll(io.LimitReader(in,maxCorpusBytes+1))
 if err!=nil{return fmt.Errorf("read corpus: %w",err)}
 if len(payload)>maxCorpusBytes{return fmt.Errorf("corpus exceeds %d byte limit",maxCorpusBytes)}
 if err:=rejectDuplicateJSONKeys(payload);err!=nil{return fmt.Errorf("corpus integrity: %w",err)}
 dec:=json.NewDecoder(bytes.NewReader(payload))
 dec.DisallowUnknownFields()
 var samples []qualification.Sample
 if err:=dec.Decode(&samples);err!=nil{return fmt.Errorf("decode corpus: %w",err)}
 var extra any
 if err:=dec.Decode(&extra);err!=io.EOF {
  if err==nil{return errors.New("trailing JSON content")}
  return fmt.Errorf("trailing input: %w",err)
 }
 report,err:=qualification.Evaluate(samples,*threshold);if err!=nil{return err}
 enc:=json.NewEncoder(out);enc.SetIndent("","  ")
 if *maxFP>=0 || *minRecall>=0 || *minPrecision>=0 || *auditCorpus || *boundaryMargin>=0 {
  result:=struct{Evaluation qualification.Report `json:"evaluation"`; Gates *qualification.GateReport `json:"gates,omitempty"`; RecallGates *qualification.RecallGateReport `json:"recall_gates,omitempty"`; PrecisionGates *qualification.PrecisionGateReport `json:"precision_gates,omitempty"`; CorpusAudit *qualification.CorpusAudit `json:"corpus_audit,omitempty"`; BoundaryAudit *qualification.BoundaryAudit `json:"boundary_audit,omitempty"`}{Evaluation:report}
  if *auditCorpus { audit,err:=qualification.AuditCorpus(samples);if err!=nil{return err};result.CorpusAudit=&audit }
  if *boundaryMargin>=0 { audit,err:=qualification.AuditBoundary(samples,*threshold,*boundaryMargin);if err!=nil{return err};result.BoundaryAudit=&audit }
  passed:=true
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
