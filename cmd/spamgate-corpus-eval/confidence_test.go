package main

import (
 "bytes"
 "fmt"
 "math"
 "os"
 "path/filepath"
 "strings"
 "testing"
)

func TestWilsonUpper(t *testing.T) {
 cases:=[]struct{pos,total int; low,high float64}{
  {0,100,0.036,0.038},
  {0,1000,0.0038,0.0039},
  {1,100,0.053,0.055},
  {100,100,1,1},
 }
 for _,tc:=range cases {
  got:=wilsonUpper(tc.pos,tc.total,1.959963984540054)
  if got<tc.low || got>tc.high { t.Errorf("wilsonUpper(%d,%d)=%v",tc.pos,tc.total,got) }
 }
 if !math.IsNaN(wilsonUpper(1,0,1.96)) {t.Fatal("zero denominator accepted")}
}

func TestCorpusConfidenceAndSampleFloor(t *testing.T) {
 dir:=t.TempDir()
 path:=filepath.Join(dir,"corpus.jsonl")
 var corpus strings.Builder
 corpus.WriteString("{\"id\":\"spam\",\"truth\":\"spam\",\"score\":1}\n")
 for i:=0;i<100;i++ { corpus.WriteString("{\"id\":\"clean-"+strconvI(i)+"\",\"truth\":\"clean\",\"score\":0}\n") }
 if err:=os.WriteFile(path,[]byte(corpus.String()),0600);err!=nil {t.Fatal(err)}
 var out,errOut bytes.Buffer
 args:=[]string{"--input",path,"--min-precision","1","--min-recall","1","--max-fpr","0","--max-fpr-upper-95","0.01"}
 if code:=run(args,&out,&errOut);code!=1 {t.Fatalf("small clean corpus falsely qualified: %d %s",code,errOut.String())}
 out.Reset();errOut.Reset()
 args[len(args)-1]="0.05"
 if code:=run(args,&out,&errOut);code!=0 {t.Fatalf("expected acceptance: %d %s",code,errOut.String())}
 out.Reset();errOut.Reset()
 if code:=run(append(args,"--min-clean","101"),&out,&errOut);code!=1 {t.Fatalf("sample floor ignored: %d",code)}
 out.Reset();errOut.Reset()
 if code:=run(append(args,"--max-fpr-upper-95","NaN"),&out,&errOut);code!=2 {t.Fatalf("NaN limit accepted: %d",code)}
}
func strconvI(n int) string {return fmt.Sprint(n)}
