// Command spamgate-eval measures classifier outcomes against independently
// adjudicated labels. It does not change the running mail server or scan mail.
package main

import (
 "bufio"
 "bytes"
 "encoding/json"
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
 MinimumHam int `json:"minimum_ham"`
 MinimumSpam int `json:"minimum_spam"`
 MaximumFalsePositiveUpper95 float64 `json:"maximum_false_positive_upper_95"`
 MinimumRecallLower95 float64 `json:"minimum_recall_lower_95"`
 GatePassed bool `json:"gate_passed"`
 Limitation string `json:"limitation"`
}

// A "soft_reject" is conservatively counted as a positive intervention: it
// can delay legitimate mail even when caused by rate or greylist policy.
func readLabels(r io.Reader)(counts,error){
 var c counts
 scanner:=bufio.NewScanner(r)
 scanner.Buffer(make([]byte,4096),64<<10)
 line:=0
 for scanner.Scan(){
  line++
  raw:=bytes.TrimSpace(scanner.Bytes())
  if len(raw)==0{continue}
  var record struct{
   Label string `json:"label"`
   Action string `json:"action"`
  }
  d:=json.NewDecoder(bytes.NewReader(raw))
  d.DisallowUnknownFields()
  if err:=d.Decode(&record);err!=nil{return counts{},fmt.Errorf("line %d: invalid labelled JSON: %w",line,err)}
  var extra any
  if err:=d.Decode(&extra);err!=io.EOF{return counts{},fmt.Errorf("line %d: trailing JSON content",line)}
  if record.Label!="ham"&&record.Label!="spam"{return counts{},fmt.Errorf("line %d: label must be ham or spam",line)}
  flagged:=false
  switch record.Action{
  case "accept":flagged=false
  case "tag","quarantine","reject","soft_reject":flagged=true
  default:return counts{},fmt.Errorf("line %d: unsupported action %q",line,record.Action)
  }
  if record.Label=="ham"{
   c.Ham++
   if flagged{c.FP++}else{c.TN++}
  }else{
   c.Spam++
   if flagged{c.TP++}else{c.FN++}
  }
 }
 if err:=scanner.Err();err!=nil{return counts{},fmt.Errorf("reading labels: %w",err)}
 if c.Ham==0||c.Spam==0{return counts{},errors.New("corpus must contain both independently labelled ham and spam")}
 return c,nil
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
 r:=report{
  Counts:c,MinimumHam:minHam,MinimumSpam:minSpam,
  MaximumFalsePositiveUpper95:maxFPR,MinimumRecallLower95:minRecall,
  Limitation:"Only the supplied independently labelled corpus is measured; results are not proof of live Postfix/Dovecot delivery, corpus representativeness, or future detection performance.",
 }
 if c.Ham<=0||c.Spam<=0{return r}
 r.FalsePositiveRate=float64(c.FP)/float64(c.Ham)
 r.FalsePositiveUpper95=wilson(c.FP,c.Ham,true)
 r.Recall=float64(c.TP)/float64(c.Spam)
 r.RecallLower95=wilson(c.TP,c.Spam,false)
 if c.TP+c.FP>0{r.Precision=float64(c.TP)/float64(c.TP+c.FP)}
 r.GatePassed=c.Ham>=minHam&&c.Spam>=minSpam&&r.FalsePositiveUpper95<=maxFPR&&r.RecallLower95>=minRecall
 return r
}

func run(args []string,output,errorsOut io.Writer)int{
 fs:=flag.NewFlagSet("spamgate-eval",flag.ContinueOnError)
 fs.SetOutput(errorsOut)
 minHam:=fs.Int("min-ham",1000,"minimum independently labelled legitimate messages")
 minSpam:=fs.Int("min-spam",1000,"minimum independently labelled spam messages")
 maxFPR:=fs.Float64("max-fpr-upper",0.01,"maximum Wilson 95% upper bound for false-positive rate")
 minRecall:=fs.Float64("min-recall-lower",0.90,"minimum Wilson 95% lower bound for recall")
 if err:=fs.Parse(args);err!=nil{return 2}
 if fs.NArg()!=1||*minHam<1||*minSpam<1||math.IsNaN(*maxFPR)||math.IsNaN(*minRecall)||*maxFPR<0||*maxFPR>1||*minRecall<0||*minRecall>1{
  fmt.Fprintln(errorsOut,"usage: spamgate-eval [--min-ham=N --min-spam=N --max-fpr-upper=0.01 --min-recall-lower=0.90] labels.jsonl")
  return 2
 }
 name:=fs.Arg(0)
 if strings.TrimSpace(name)==""{fmt.Fprintln(errorsOut,"corpus path required");return 2}
 file,err:=os.Open(name)
 if err!=nil{fmt.Fprintln(errorsOut,"cannot open corpus:",err);return 2}
 defer file.Close()
 c,err:=readLabels(file)
 if err!=nil{fmt.Fprintln(errorsOut,"invalid corpus:",err);return 2}
 result:=evaluate(c,*minHam,*minSpam,*maxFPR,*minRecall)
 if err:=json.NewEncoder(output).Encode(result);err!=nil{fmt.Fprintln(errorsOut,"cannot write evaluation:",err);return 2}
 if !result.GatePassed{return 3}
 return 0
}
func main(){os.Exit(run(os.Args[1:],os.Stdout,os.Stderr))}
