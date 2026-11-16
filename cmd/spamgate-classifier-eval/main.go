// spamgate-classifier-eval evaluates labeled offline corpora without altering live mail.
package main

import (
 "encoding/json"
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
 dec:=json.NewDecoder(io.LimitReader(in,32<<20))
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
 if *maxFP>=0 || *minRecall>=0 || *minPrecision>=0 || *auditCorpus {
  result:=struct{Evaluation qualification.Report `json:"evaluation"`; Gates *qualification.GateReport `json:"gates,omitempty"`; RecallGates *qualification.RecallGateReport `json:"recall_gates,omitempty"`; PrecisionGates *qualification.PrecisionGateReport `json:"precision_gates,omitempty"`; CorpusAudit *qualification.CorpusAudit `json:"corpus_audit,omitempty"`}{Evaluation:report}
  if *auditCorpus { audit,err:=qualification.AuditCorpus(samples);if err!=nil{return err};result.CorpusAudit=&audit }
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
func main(){
 if err:=run(os.Args[1:],os.Stdin,os.Stdout);err!=nil{
  fmt.Fprintln(os.Stderr,"classifier evaluation:",strings.TrimSpace(err.Error()))
  os.Exit(1)
 }
}
