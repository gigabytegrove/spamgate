package main

import (
 "bytes"
 "strings"
 "testing"
)

func TestCorpusDuplicateKeysFailClosed(t *testing.T){
 cases:=[]string{
  `[{"id":"a","tenant":"t","spam":false,"spam":true,"score":1}]`,
  `[{"id":"a","tenant":"t","spam":false,"score":1,"score":10}]`,
  `[{"id":"a","tenant":"t","spam":false,"score":1,"tenant":"other"}]`,
  `[{"id":"a","tenant":"t","spam":false,"score":1,"id":"b"}]`,
  `[{"id":"a","tenant":"t","spam":false,"score":1,"extra":{"x":1,"x":2}}]`,
 }
 for _,corpus:=range cases {
  var out bytes.Buffer
  err:=run(nil,strings.NewReader(corpus),&out)
  if err==nil||!strings.Contains(err.Error(),"duplicate JSON object key"){t.Fatalf("duplicate accepted: %v",err)}
  if out.Len()!=0{t.Fatalf("report emitted on invalid corpus: %s",out.String())}
 }
}

func TestCorpusDuplicateKeysEscapedEquivalence(t *testing.T){
 corpus:=`[{"id":"a","tenant":"t","spam":false,"score":1,"sp\\u0061m":true}]`
 var out bytes.Buffer
 if err:=run(nil,strings.NewReader(corpus),&out);err==nil{t.Fatal("escaped duplicate key accepted")}
}

func TestCorpusStrictJSONAcceptsValidInput(t *testing.T){
 var out bytes.Buffer
 if err:=run(nil,strings.NewReader(oneSample),&out);err!=nil{t.Fatal(err)}
 if !strings.Contains(out.String(),`"threshold": 5`){t.Fatal("report missing")}
}

func TestCorpusStrictJSONRejectsTrailingValues(t *testing.T){
 var out bytes.Buffer
 if err:=run(nil,strings.NewReader(oneSample+" true"),&out);err==nil{t.Fatal("trailing value accepted")}
 if out.Len()!=0{t.Fatal("report emitted")}
}
