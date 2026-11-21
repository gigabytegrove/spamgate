package main

import (
 "math"
 "testing"
)

func TestPairedRegressionExactProbability(t *testing.T) {
 cases:=[]struct{ regressions,fixes int; want float64 }{
  {0,0,1},{0,1,1},{1,0,0.5},{2,0,0.25},
  {3,1,0.3125},{1,3,0.9375},{5,5,0.623046875},
  {10,0,1.0/1024},{0,10,1},
 }
 for _,tc:=range cases {
  got:=pairedRegressionP(tc.regressions,tc.fixes)
  if math.Abs(got-tc.want)>1e-12 {t.Fatalf("p(%d,%d)=%g want %g",tc.regressions,tc.fixes,got,tc.want)}
 }
 if !math.IsNaN(pairedRegressionP(-1,0)) {t.Fatal("negative counts accepted")}
}
func TestPairedRegressionLargeCorpusStable(t *testing.T) {
 for _,tc:=range [][2]int{{10000,0},{0,10000},{5000,5000},{5100,4900}} {
  p:=pairedRegressionP(tc[0],tc[1])
  if math.IsNaN(p)||math.IsInf(p,0)||p<0||p>1 {t.Fatalf("invalid p for %v: %v",tc,p)}
 }
 if pairedRegressionP(10000,0)>1e-100 {t.Fatal("extreme regression should have tiny p")}
}
func TestPairedRegressionReport(t *testing.T) {
 b:=map[string]comparisonSample{
 "c1":{ID:"c1",Truth:"clean",Score:0.1},
 "c2":{ID:"c2",Truth:"clean",Score:0.9},
 "s1":{ID:"s1",Truth:"spam",Score:0.9},
 "s2":{ID:"s2",Truth:"spam",Score:0.1},
 }
 c:=map[string]comparisonSample{
 "c1":{ID:"c1",Truth:"clean",Score:0.9},
 "c2":{ID:"c2",Truth:"clean",Score:0.1},
 "s1":{ID:"s1",Truth:"spam",Score:0.1},
 "s2":{ID:"s2",Truth:"spam",Score:0.9},
 }
 r,err:=compareCorpora(b,c,0.5)
 if err!=nil {t.Fatal(err)}
 if r.CleanRegressionPValue!=0.75||r.SpamRegressionPValue!=0.75 {t.Fatalf("unexpected paired evidence %+v",r)}
}
