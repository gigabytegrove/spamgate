package main

import (
 "bytes"
 "math"
 "strings"
 "testing"
)

func TestFiniteProbabilityRejectsNonFiniteValues(t *testing.T) {
 for _, value := range []float64{math.NaN(), math.Inf(1), math.Inf(-1)} {
  if finiteProbability(value) { t.Fatalf("accepted non-finite value %v",value) }
 }
 for _, value := range []float64{0, 0.5, 1} {
  if !finiteProbability(value) { t.Fatalf("rejected finite value %v",value) }
 }
}

// The validation must happen before opening the corpus or emitting any
// apparently qualifying report. A missing path is intentional: invalid
// thresholds must fail independently of the input file's existence.
func TestNonFiniteThresholdsFailClosed(t *testing.T) {
 flags := []string{
  "max-fpr-upper", "min-recall-lower", "min-precision-lower",
  "max-cohort-fpr-upper", "min-cohort-recall-lower", "min-cohort-precision-lower",
 }
 for _, name := range flags {
  for _, value := range []string{"+Inf", "-Inf", "NaN"} {
   t.Run(name+"/"+value,func(t *testing.T) {
    var out, errout bytes.Buffer
    args:=[]string{"--"+name+"="+value,"nonexistent-corpus.jsonl"}
    if name=="min-cohort-precision-lower" { args=append([]string{"--require-cohorts"},args...) }
    code:=run(args,&out,&errout)
    if code!=2 {t.Fatalf("expected invalid configuration exit 2; got %d: %s",code,errout.String())}
    if out.Len()!=0 {t.Fatalf("invalid threshold emitted report: %s",out.String())}
    if !strings.Contains(errout.String(),"usage:") && !strings.Contains(errout.String(),"invalid value") {
     t.Fatalf("missing actionable validation error: %s",errout.String())
    }
   })
  }
 }
}
