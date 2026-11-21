package main

import (
 "strings"
 "testing"
)
func TestCompareCorpora(t *testing.T){
 baseline:=`{"id":"a","truth":"clean","score":0.1}
{"id":"b","truth":"clean","score":0.8}
{"id":"c","truth":"spam","score":0.9}
{"id":"d","truth":"spam","score":0.1}
`
 candidate:=`{"id":"a","truth":"clean","score":0.7}
{"id":"b","truth":"clean","score":0.2}
{"id":"c","truth":"spam","score":0.1}
{"id":"d","truth":"spam","score":0.8}
`
 b,err:=loadCorpus(strings.NewReader(baseline));if err!=nil{t.Fatal(err)}
 c,err:=loadCorpus(strings.NewReader(candidate));if err!=nil{t.Fatal(err)}
 r,err:=compareCorpora(b,c,0.5);if err!=nil{t.Fatal(err)}
 if r.Total!=4||r.NewFalsePositives!=1||r.FixedFalsePositives!=1||r.NewFalseNegatives!=1||r.FixedFalseNegatives!=1||r.NewFalsePositiveIDs[0]!="a"||r.NewFalseNegativeIDs[0]!="c"{t.Fatalf("unexpected report: %+v",r)}
}
func TestCompareRejectsEvidenceDrift(t *testing.T){
 b:=map[string]comparisonSample{"a":{ID:"a",Truth:"clean",Score:0.1},"b":{ID:"b",Truth:"spam",Score:0.9}}
 for _,tc:=range []struct{name string;c map[string]comparisonSample;threshold float64}{
  {"missing",map[string]comparisonSample{"a":b["a"]},0.5},
  {"changed label",map[string]comparisonSample{"a":{ID:"a",Truth:"spam",Score:0.1},"b":b["b"]},0.5},
  {"invalid score",map[string]comparisonSample{"a":{ID:"a",Truth:"clean",Score:2},"b":b["b"]},0.5},
  {"invalid threshold",b,2},
 }{t.Run(tc.name,func(t *testing.T){if _,err:=compareCorpora(b,tc.c,tc.threshold);err==nil{t.Fatal("expected refusal")}})}
}
func TestLoadCorpusRejectsDuplicatesAndMalformed(t *testing.T){
 for _,raw:=range []string{
  "{\"id\":\"a\",\"truth\":\"clean\",\"score\":0.1}\n{\"id\":\"a\",\"truth\":\"spam\",\"score\":0.8}",
  "{\"id\":\"a\",\"truth\":\"clean\",\"score\":0.1,\"score\":0.2}",
  "{\"id\":\"a\",\"truth\":\"clean\"}",
 }{if _,err:=loadCorpus(strings.NewReader(raw));err==nil{t.Fatalf("accepted invalid corpus: %s",raw)}}
}
