// Command spamgate-eval measures classifier outcomes against independently
// adjudicated labels. It does not change the running mail server or scan mail.
package main

import (
 "bufio"
 "bytes"
 "encoding/json"
 "encoding/hex"
 "errors"
 "flag"
 "fmt"
 "io"
 "math"
 "os"
 "strings"
)

type counts struct{
 Ham int `json:"ham"`
 Spam int `json:"spam"`
 TP int `json:"true_positive"`
 FP int `json:"false_positive"`
 TN int `json:"true_negative"`
 FN int `json:"false_negative"`
}

type report struct{
 Counts counts `json:"counts"`
 FalsePositiveRate float64 `json:"false_positive_rate"`
 FalsePositiveUpper95 float64 `json:"false_positive_upper_95"`
 Recall float64 `json:"recall"`
 RecallLower95 float64 `json:"recall_lower_95"`
 Precision float64 `json:"precision"`
 PrecisionLower95 float64 `json:"precision_lower_95"`
 MinimumPrecisionLower95 float64 `json:"minimum_precision_lower_95"`
 MinimumHam int `json:"minimum_ham"`
 MinimumSpam int `json:"minimum_spam"`
 MaximumFalsePositiveUpper95 float64 `json:"maximum_false_positive_upper_95"`
 MinimumRecallLower95 float64 `json:"minimum_recall_lower_95"`
 GatePassed bool `json:"gate_passed"`
 Cohorts []cohortResult `json:"cohorts,omitempty"`
 CohortGatePassed bool `json:"cohort_gate_passed"`
 UnspecifiedCohort int `json:"unspecified_cohort"`
 CohortGateRequired bool `json:"cohort_gate_required"`
 Limitation string `json:"limitation"`
}

// A "soft_reject" is conservatively counted as a positive intervention: it
// can delay legitimate mail even when caused by rate or greylist policy.
func readLabels(r io.Reader)(counts,error){
 c,_,_,err:=readLabelledCorpus(r)
 return c,err
}

// readLabelledCorpus accepts only category names, never message identifiers or
// raw mail. The legacy two-field format remains valid and unstratified.
func readLabelledCorpus(r io.Reader)(counts,map[string]counts,int,error){
 return readLabelledCorpusWithOptions(r,false)
}

// With strict IDs enabled, a privacy-preserving SHA-256 digest must identify
// each independently adjudicated message exactly once across all cohorts.
// This prevents repeated examples from inflating sample sizes and confidence.
func readLabelledCorpusWithOptions(r io.Reader,requireUniqueIDs bool)(counts,map[string]counts,int,error){
 return readLabelledCorpusWithLimit(r,requireUniqueIDs,1000000)
}

// Bound the number of accepted examples independently of the JSONL record size.
// This protects the unique-ID map and per-record accounting against unbounded input.
func readLabelledCorpusWithLimit(r io.Reader,requireUniqueIDs bool,maxRecords int)(counts,map[string]counts,int,error){
 return readLabelledCorpusWithBudgets(r,requireUniqueIDs,maxRecords,128<<20)
}

// A byte budget also bounds whitespace-only and malformed input that never
// increments the accepted-record budget. One extra byte detects overflow.
func readLabelledCorpusWithBudgets(r io.Reader,requireUniqueIDs bool,maxRecords int,maxBytes int64)(counts,map[string]counts,int,error){
 var c counts
 if maxBytes<1 || maxBytes==math.MaxInt64{return counts{},nil,0,errors.New("maximum input bytes must be positive and allow overflow detection")}
 limited:=&io.LimitedReader{R:r,N:maxBytes+1}
 if maxRecords<1{return counts{},nil,0,errors.New("maximum records must be positive")}
 seen:=map[string]struct{}{}
 cohorts:=map[string]counts{}
 unspecified:=0
 scanner:=bufio.NewScanner(limited)
 scanner.Buffer(make([]byte,4096),64<<10)
 line:=0
 for scanner.Scan(){
  line++
  raw:=bytes.TrimSpace(scanner.Bytes())
  if len(raw)==0{continue}
  if c.Ham+c.Spam>=maxRecords{return counts{},nil,0,fmt.Errorf("line %d: corpus exceeds maximum of %d records",line,maxRecords)}
  record, err := parseCorpusRecord(raw)
  if err != nil {return counts{},nil,0,fmt.Errorf("line %d: invalid labelled JSON: %w",line,err)}
  if record.Label!="ham"&&record.Label!="spam"{return counts{},nil,0,fmt.Errorf("line %d: label must be ham or spam",line)}
  if record.ID=="" && requireUniqueIDs {return counts{},nil,0,fmt.Errorf("line %d: strict corpus requires a SHA-256 id for every message",line)}
  if record.ID!="" {
   if len(record.ID)!=64 || strings.ToLower(record.ID)!=record.ID {return counts{},nil,0,fmt.Errorf("line %d: id must be 64 lowercase hexadecimal characters",line)}
   if _,err:=hex.DecodeString(record.ID);err!=nil{return counts{},nil,0,fmt.Errorf("line %d: invalid SHA-256 id",line)}
   if _,exists:=seen[record.ID];exists{return counts{},nil,0,fmt.Errorf("line %d: duplicate corpus id",line)}
   seen[record.ID]=struct{}{}
  }
  flagged:=false
  switch record.Action{
  case "accept":flagged=false
  case "tag","quarantine","reject","soft_reject":flagged=true
  default:return counts{},nil,0,fmt.Errorf("line %d: unsupported action",line)
  }
  if record.Cohort!=""&&!validEvaluationCohort(record.Cohort){
   return counts{},nil,0,fmt.Errorf("line %d: unsupported privacy-safe cohort",line)
  }
  addEvaluationOutcome(&c,record.Label,flagged)
  if record.Cohort==""{
   unspecified++
  }else{
   x:=cohorts[record.Cohort]
   addEvaluationOutcome(&x,record.Label,flagged)
   cohorts[record.Cohort]=x
  }
 }
 if err:=scanner.Err();err!=nil{return counts{},nil,0,fmt.Errorf("reading labels: %w",err)}
 if limited.N==0{return counts{},nil,0,fmt.Errorf("corpus exceeds maximum of %d input bytes",maxBytes)}
 if c.Ham==0||c.Spam==0{return counts{},nil,0,errors.New("corpus must contain both independently labelled ham and spam")}
 return c,cohorts,unspecified,nil
}

// Wilson interval avoids reporting 0% observed false positives as proof of
// zero future risk. z=1.959963984540054 gives a two-sided 95% interval.
func wilson(success,total int,upper bool)float64{
 if total<=0{return 0}
 n:=float64(total)
 p:=float64(success)/n
 z:=1.959963984540054
 den:=1+z*z/n
 center:=(p+z*z/(2*n))/den
 margin:=z*math.Sqrt((p*(1-p)+z*z/(4*n))/n)/den
 if upper{return math.Min(1,center+margin)}
 return math.Max(0,center-margin)
}

func evaluate(c counts,minHam,minSpam int,maxFPR,minRecall float64)report{
 return evaluateWithPrecision(c,minHam,minSpam,maxFPR,minRecall,0)
}

// Precision is a separate safety gate: recall alone cannot detect a classifier
// that flags almost every legitimate message. A zero positive-prediction sample
// never qualifies when a positive precision threshold is required.
func evaluateWithPrecision(c counts,minHam,minSpam int,maxFPR,minRecall,minPrecision float64)report{
 r:=report{
  Counts:c,MinimumHam:minHam,MinimumSpam:minSpam,
  MinimumPrecisionLower95:minPrecision,
  MaximumFalsePositiveUpper95:maxFPR,MinimumRecallLower95:minRecall,
  Limitation:"Only the supplied independently labelled corpus is measured; results are not proof of live Postfix/Dovecot delivery, corpus representativeness, or future detection performance.",
 }
 if c.Ham<=0||c.Spam<=0{return r}
 r.FalsePositiveRate=float64(c.FP)/float64(c.Ham)
 r.FalsePositiveUpper95=wilson(c.FP,c.Ham,true)
 r.Recall=float64(c.TP)/float64(c.Spam)
 r.RecallLower95=wilson(c.TP,c.Spam,false)
 if c.TP+c.FP>0{
  r.Precision=float64(c.TP)/float64(c.TP+c.FP)
  r.PrecisionLower95=wilson(c.TP,c.TP+c.FP,false)
 }
 r.GatePassed=c.Ham>=minHam&&c.Spam>=minSpam&&r.FalsePositiveUpper95<=maxFPR&&r.RecallLower95>=minRecall&&(minPrecision==0||(c.TP+c.FP>0&&r.PrecisionLower95>=minPrecision))
 return r
}

// Reject non-finite CLI thresholds before evaluation or JSON encoding. In
// particular, +Inf must never disable a false-positive upper-bound gate.
func finiteProbability(v float64) bool { return !math.IsNaN(v) && !math.IsInf(v,0) }

func run(args []string,output,errorsOut io.Writer)int{
 fs:=flag.NewFlagSet("spamgate-eval",flag.ContinueOnError)
 fs.SetOutput(errorsOut)
 minHam:=fs.Int("min-ham",1000,"minimum independently labelled legitimate messages")
 minSpam:=fs.Int("min-spam",1000,"minimum independently labelled spam messages")
 maxFPR:=fs.Float64("max-fpr-upper",0.01,"maximum Wilson 95% upper bound for false-positive rate")
 minRecall:=fs.Float64("min-recall-lower",0.90,"minimum Wilson 95% lower bound for recall")
 minPrecision:=fs.Float64("min-precision-lower",0,"minimum Wilson 95% lower bound for precision (0 disables precision gating)")
 requireCohorts:=fs.Bool("require-cohorts",false,"require at least two sufficiently powered independently labelled cohorts")
 requireUniqueIDs:=fs.Bool("require-unique-ids",false,"require distinct SHA-256 message IDs to prevent repeated samples from inflating confidence")
 maxRecords:=fs.Int("max-records",1000000,"maximum labelled records accepted (memory and CPU safety limit)")
 maxInputBytes:=fs.Int64("max-input-bytes",128<<20,"maximum corpus bytes including whitespace (default 134217728)")
 minCohortHam:=fs.Int("min-cohort-ham",100,"minimum ham per cohort when required")
 minCohortSpam:=fs.Int("min-cohort-spam",100,"minimum spam per cohort when required")
 maxCohortFPR:=fs.Float64("max-cohort-fpr-upper",0.05,"maximum Wilson upper false-positive bound per cohort")
 minCohortRecall:=fs.Float64("min-cohort-recall-lower",0.75,"minimum Wilson lower recall bound per cohort")
 minCohortPrecision:=fs.Float64("min-cohort-precision-lower",0,"minimum Wilson lower precision bound per cohort (0 disables this gate)")
 if err:=fs.Parse(args);err!=nil{return 2}
 // Explicit cohort acceptance thresholds must not silently become report-only.
 // A zero precision threshold is a documented disabled gate; all other
 // cohort thresholds, including explicit zero FPR/recall, require enforcement.
 cohortThresholds:=map[string]bool{
  "min-cohort-ham":true,"min-cohort-spam":true,
  "max-cohort-fpr-upper":true,"min-cohort-recall-lower":true,
 }
  if !*requireCohorts {
  var configured []string
  fs.Visit(func(f *flag.Flag){
   if f.Name=="min-cohort-precision-lower" && *minCohortPrecision>0 {configured=append(configured,"--"+f.Name);return}
   if cohortThresholds[f.Name]{configured=append(configured,"--"+f.Name)}
  })
  if len(configured)>0 {fmt.Fprintf(errorsOut,"%s requires --require-cohorts; refusing unenforced cohort acceptance thresholds\n",strings.Join(configured,", "));return 2}
 }
 if fs.NArg()!=1||*maxRecords<1||*minHam>*maxRecords||*minSpam>*maxRecords||int64(*minHam)+int64(*minSpam)>int64(*maxRecords)||*maxInputBytes<1||*maxInputBytes==math.MaxInt64||*minHam<1||*minSpam<1||!finiteProbability(*maxFPR)||!finiteProbability(*minRecall)||!finiteProbability(*minPrecision)||*minPrecision<0||*minPrecision>1||*maxFPR<0||*maxFPR>1||*minRecall<0||*minRecall>1||*minCohortHam<1||*minCohortSpam<1||!finiteProbability(*maxCohortFPR)||!finiteProbability(*minCohortRecall)||!finiteProbability(*minCohortPrecision)||*minCohortPrecision<0||*minCohortPrecision>1||*maxCohortFPR<0||*maxCohortFPR>1||*minCohortRecall<0||*minCohortRecall>1{
  fmt.Fprintln(errorsOut,"usage: spamgate-eval [--min-ham=N --min-spam=N --max-fpr-upper=0.01 --min-recall-lower=0.90] labels.jsonl")
  return 2
 }
 name:=fs.Arg(0)
 if strings.TrimSpace(name)==""{fmt.Fprintln(errorsOut,"corpus path required");return 2}
 file,err:=os.Open(name)
 if err!=nil{fmt.Fprintln(errorsOut,"cannot open corpus:",err);return 2}
 defer file.Close()
 c,cohorts,unspecified,err:=readLabelledCorpusWithBudgets(file,*requireUniqueIDs,*maxRecords,*maxInputBytes)
 if err!=nil{fmt.Fprintln(errorsOut,"invalid corpus:",err);return 2}
 result:=evaluateWithPrecision(c,*minHam,*minSpam,*maxFPR,*minRecall,*minPrecision)
 result.Cohorts,result.CohortGatePassed=evaluateCohortsWithPrecision(cohorts,unspecified,*minCohortHam,*minCohortSpam,*maxCohortFPR,*minCohortRecall,*minCohortPrecision)
 result.UnspecifiedCohort=unspecified
 result.CohortGateRequired=*requireCohorts
 if *requireCohorts {result.GatePassed=result.GatePassed&&result.CohortGatePassed}
 if err:=json.NewEncoder(output).Encode(result);err!=nil{fmt.Fprintln(errorsOut,"cannot write evaluation:",err);return 2}
 if !result.GatePassed{return 3}
 return 0
}
func main(){os.Exit(run(os.Args[1:],os.Stdout,os.Stderr))}
