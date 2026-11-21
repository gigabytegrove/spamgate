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

type comparisonSample struct { ID string; Truth string; Score float64 }
type comparisonReport struct {
 Total int `json:"total"`
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
}
func loadCorpus(r io.Reader) (map[string]comparisonSample,error) {
 scan:=bufio.NewScanner(r);scan.Buffer(make([]byte,4096),4*1024*1024)
 samples:=make(map[string]comparisonSample)
 for line:=1;scan.Scan();line++ {
  raw:=strings.TrimSpace(scan.Text());if raw=="" {continue}
  s,err:=decodeSample(raw);if err!=nil{return nil,fmt.Errorf("line %d: %w",line,err)}
  if s.ID=="" || (s.Truth!="clean" && s.Truth!="spam") || !(s.Score>=0 && s.Score<=1) {return nil,fmt.Errorf("line %d: invalid sample",line)}
  if _,exists:=samples[s.ID];exists{return nil,fmt.Errorf("line %d: duplicate id %q",line,s.ID)}
  samples[s.ID]=comparisonSample{ID:s.ID,Truth:s.Truth,Score:s.Score}
 }
 if err:=scan.Err();err!=nil{return nil,err}
 if len(samples)==0{return nil,errors.New("empty corpus")}
 return samples,nil
}
func compareCorpora(baseline,candidate map[string]comparisonSample,threshold float64)(comparisonReport,error){
 r:=comparisonReport{NewFalsePositiveIDs:[]string{},NewFalseNegativeIDs:[]string{}}
 if !(threshold>=0 && threshold<=1){return r,errors.New("threshold must be between 0 and 1")}
 if len(baseline)!=len(candidate){return r,errors.New("corpus sample count differs")}
 for id,b:=range baseline {
  c,ok:=candidate[id];if !ok{return r,fmt.Errorf("candidate missing sample %q",id)}
  if b.Truth!=c.Truth{return r,fmt.Errorf("ground truth changed for %q",id)}
  if !(b.Score>=0&&b.Score<=1&&c.Score>=0&&c.Score<=1){return r,fmt.Errorf("invalid score for %q",id)}
  oldPositive:=b.Score>=threshold;newPositive:=c.Score>=threshold
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
 maxCandidateUpper:=f.Float64("max-candidate-fpr-upper-95",1,"maximum candidate Wilson 95 percent upper false-positive bound")
 if err:=f.Parse(args);err!=nil{return 2}
 if *baselinePath==""||*candidatePath==""||*baselinePath==*candidatePath||f.NArg()!=0||*maxNewFP<0||*maxNewFN<0||*minClean<1||*minSpam<1||!(*maxCandidateFPR>=0&&*maxCandidateFPR<=1)||!(*maxCandidateUpper>=0&&*maxCandidateUpper<=1)||!(*threshold>=0&&*threshold<=1){fmt.Fprintln(stderr,"invalid arguments");return 2}
 bf,err:=os.Open(*baselinePath);if err!=nil{fmt.Fprintln(stderr,err);return 2};defer bf.Close()
 cf,err:=os.Open(*candidatePath);if err!=nil{fmt.Fprintln(stderr,err);return 2};defer cf.Close()
 b,err:=loadCorpus(bf);if err!=nil{fmt.Fprintln(stderr,"baseline:",err);return 2}
 c,err:=loadCorpus(cf);if err!=nil{fmt.Fprintln(stderr,"candidate:",err);return 2}
 report,err:=compareCorpora(b,c,*threshold);if err!=nil{fmt.Fprintln(stderr,err);return 2}
 if err:=json.NewEncoder(stdout).Encode(report);err!=nil{fmt.Fprintln(stderr,err);return 2}
 if report.Clean<*minClean||report.Spam<*minSpam||report.CandidateFalsePositiveRate>*maxCandidateFPR||report.CandidateFalsePositiveUpper95>*maxCandidateUpper||report.NewFalsePositives>*maxNewFP||report.NewFalseNegatives>*maxNewFN{fmt.Fprintln(stderr,"classifier regression gate failed");return 1}
 return 0
}
func main(){os.Exit(compareRun(os.Args[1:],os.Stdout,os.Stderr))}
