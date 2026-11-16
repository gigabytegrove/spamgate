package main

import (
 "bytes"
 "fmt"
 "strings"
 "testing"
)

const oneSample = `[{"id":"s1","tenant":"alpha","spam":true,"score":5}]`

func TestExplicitInvalidQualificationOptionsFailClosed(t *testing.T) {
 cases:=[][]string{
  {"-max-fp-upper=-0.01"},
  {"-min-recall=-0.01"},
  {"-min-precision=-0.01"},
  {"-max-fp-upper=1.01"},
  {"-min-recall=1.01"},
  {"-min-precision=1.01"},
  {"-audit-boundary-margin=-0.1"},
  {"-audit-boundary-margin=NaN"},
  {"-audit-boundary-margin=+Inf"},
  {"-max-fp-upper=NaN"},
  {"-min-recall=NaN"},
  {"-min-precision=+Inf"},
  {"-min-clean=0"},
  {"-min-spam=0"},
  {"-min-predicted-spam=0"},
  {"-z-score=0"},
  {"-z-score=NaN"},
  {"-z-score=11"},
  {"-threshold=NaN"},
 }
 for _,args:=range cases {
  t.Run(strings.Join(args,"_"),func(t *testing.T){
   var out bytes.Buffer
   if err:=run(args,strings.NewReader(oneSample),&out);err==nil {
    t.Fatalf("invalid options %v accepted: %s",args,out.String())
   }
   if out.Len()!=0 {t.Fatalf("wrote qualification report for invalid options: %s",out.String())}
  })
 }
}

func TestExplicitZeroGateIsEnforced(t *testing.T) {
 // A legitimate message predicted as spam must fail a zero-FP acceptance gate.
 corpus:=`[{"id":"c1","tenant":"alpha","spam":false,"score":9}]`
 var out bytes.Buffer
 err:=run([]string{"-max-fp-upper=0","-min-clean=1"},strings.NewReader(corpus),&out)
 if err==nil {t.Fatal("zero false-positive bound was silently disabled")}
 if !strings.Contains(out.String(),`"passed": false`){t.Fatalf("missing failed gate evidence: %s",out.String())}
}

func TestCorpusSizeLimitIncludesTrailingBytes(t *testing.T) {
 // A valid prefix plus excessive whitespace must not evade the 32 MiB bound.
 input:=oneSample+strings.Repeat(" ",32<<20)
 var out bytes.Buffer
 err:=run(nil,strings.NewReader(input),&out)
 if err==nil||!strings.Contains(err.Error(),"byte limit"){t.Fatalf("oversized input: %v",err)}
 if out.Len()!=0 {t.Fatal("oversized input emitted a report")}
}

func TestCorpusExactlyAtLimit(t *testing.T) {
 input:=oneSample+strings.Repeat(" ",(32<<20)-len(oneSample))
 var out bytes.Buffer
 if err:=run(nil,strings.NewReader(input),&out);err!=nil{t.Fatal(err)}
 if !strings.Contains(out.String(),`"threshold": 5`){t.Fatal(fmt.Sprintf("missing report: %s",out.String()))}
}
