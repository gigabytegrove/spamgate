package main

import (
 "bufio"
 "encoding/json"
 "errors"
 "flag"
 "fmt"
 "math"
 "io"
 "os"
 "strings"
)

type Sample struct { ID string `json:"id"`; Truth string `json:"truth"`; Score float64 `json:"score"` }
type Report struct { Total int `json:"total"`; TP int `json:"tp"`; FP int `json:"fp"`; TN int `json:"tn"`; FN int `json:"fn"`; Precision float64 `json:"precision"`; Recall float64 `json:"recall"`; FalsePositiveRate float64 `json:"false_positive_rate"`; FalsePositiveUpper95 float64 `json:"false_positive_upper_95"`; CleanSamples int `json:"clean_samples"`; SpamSamples int `json:"spam_samples"`; Threshold float64 `json:"threshold"` }
func evaluate(r io.Reader, threshold float64) (Report,error) {
 out:=Report{Threshold:threshold}; if !(threshold>=0&&threshold<=1){return out,errors.New("threshold must be between 0 and 1")}
 scan:=bufio.NewScanner(r);scan.Buffer(make([]byte,4096),4*1024*1024)
 seen:=map[string]struct{}{}
 for line:=1;scan.Scan();line++ { raw:=strings.TrimSpace(scan.Text());if raw==""{continue}
 s,err:=decodeSample(raw);if err!=nil{return out,fmt.Errorf("line %d: %w",line,err)}
 if s.ID==""{return out,fmt.Errorf("line %d: missing id",line)};if _,ok:=seen[s.ID];ok{return out,fmt.Errorf("line %d: duplicate id %q",line,s.ID)};seen[s.ID]=struct{}{}
 if s.Truth!="spam"&&s.Truth!="clean"{return out,fmt.Errorf("line %d: truth must be spam or clean",line)}
 if !(s.Score>=0&&s.Score<=1){return out,fmt.Errorf("line %d: score outside [0,1]",line)}
 predicted:=s.Score>=threshold
 switch {case s.Truth=="spam"&&predicted:out.TP++;case s.Truth=="spam":out.FN++;case predicted:out.FP++;default:out.TN++};out.Total++
 };if err:=scan.Err();err!=nil{return out,err};if out.Total==0{return out,errors.New("empty corpus")};if out.TP+out.FN==0||out.TN+out.FP==0{return out,errors.New("corpus requires both spam and clean ground truth")}
 out.CleanSamples=out.TN+out.FP;out.SpamSamples=out.TP+out.FN;out.FalsePositiveUpper95=wilsonUpper(out.FP,out.CleanSamples,1.959963984540054)
 if out.TP+out.FP>0{out.Precision=float64(out.TP)/float64(out.TP+out.FP)};out.Recall=float64(out.TP)/float64(out.TP+out.FN);out.FalsePositiveRate=float64(out.FP)/float64(out.TN+out.FP);return out,nil
}
func run(args []string, stdout,stderr io.Writer) int {
 f:=flag.NewFlagSet("spamgate-corpus-eval",flag.ContinueOnError);f.SetOutput(stderr)
 input:=f.String("input","","JSONL corpus path");threshold:=f.Float64("threshold",0.5,"spam threshold");minPrecision:=f.Float64("min-precision",0.99,"minimum precision");minRecall:=f.Float64("min-recall",0.90,"minimum recall");maxFPR:=f.Float64("max-fpr",0.001,"maximum clean-message false-positive rate");maxUpper:=f.Float64("max-fpr-upper-95",1,"maximum Wilson 95 percent upper confidence bound for false-positive rate");minClean:=f.Int("min-clean",1,"minimum independently labeled clean samples");minSpam:=f.Int("min-spam",1,"minimum independently labeled spam samples")
 if err:=f.Parse(args);err!=nil{return 2};if *input==""||f.NArg()!=0||*minPrecision<0||*minPrecision>1||*minRecall<0||*minRecall>1||*maxFPR<0||*maxFPR>1||math.IsNaN(*minPrecision)||math.IsNaN(*minRecall)||math.IsNaN(*maxFPR)||math.IsNaN(*maxUpper)||*maxUpper<0||*maxUpper>1||*minClean<1||*minSpam<1{fmt.Fprintln(stderr,"invalid arguments or limits");return 2}
 file,err:=os.Open(*input);if err!=nil{fmt.Fprintln(stderr,err);return 2};defer file.Close()
 report,err:=evaluate(file,*threshold);if err!=nil{fmt.Fprintln(stderr,err);return 2};if err:=json.NewEncoder(stdout).Encode(report);err!=nil{fmt.Fprintln(stderr,err);return 2}
 if report.CleanSamples<*minClean||report.SpamSamples<*minSpam||report.Precision<*minPrecision||report.Recall<*minRecall||report.FalsePositiveRate>*maxFPR||report.FalsePositiveUpper95>*maxUpper{fmt.Fprintln(stderr,"classifier acceptance limits failed");return 1};return 0
}
func main(){os.Exit(run(os.Args[1:],os.Stdout,os.Stderr))}
