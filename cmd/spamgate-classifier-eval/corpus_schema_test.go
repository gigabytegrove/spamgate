package main

import (
 "bytes"
 "strings"
 "testing"
)

func TestCorpusSchemaFailClosed(t *testing.T) {
 cases:=[]struct{name,corpus string}{
  {"missing label",`[{"id":"a","tenant":"t","score":5}]`},
  {"missing score",`[{"id":"a","tenant":"t","spam":true}]`},
  {"missing tenant",`[{"id":"a","spam":true,"score":5}]`},
  {"missing ID",`[{"tenant":"t","spam":true,"score":5}]`},
  {"null label",`[{"id":"a","tenant":"t","spam":null,"score":5}]`},
  {"null score",`[{"id":"a","tenant":"t","spam":true,"score":null}]`},
  {"null ID",`[{"id":null,"tenant":"t","spam":true,"score":5}]`},
  {"string label",`[{"id":"a","tenant":"t","spam":"false","score":5}]`},
  {"string score",`[{"id":"a","tenant":"t","spam":false,"score":"5"}]`},
  {"null record",`[null]`},
  {"null corpus",`null`},
  {"object corpus",`{"id":"a","tenant":"t","spam":true,"score":5}`},
 }
 for _,tc:=range cases {
  t.Run(tc.name,func(t *testing.T){
   var out bytes.Buffer
   if err:=run(nil,strings.NewReader(tc.corpus),&out);err==nil{t.Fatal("invalid corpus accepted")}
   if out.Len()!=0{t.Fatalf("invalid corpus produced report: %s",out.String())}
  })
 }
}

func TestCorpusSchemaAllowsExplicitFalseAndZero(t *testing.T){
 var out bytes.Buffer
 corpus:=`[{"id":"a","tenant":"t","spam":false,"score":0}]`
 if err:=run(nil,strings.NewReader(corpus),&out);err!=nil{t.Fatal(err)}
 if !strings.Contains(out.String(),`"true_negative": 1`){t.Fatalf("incorrect report: %s",out.String())}
}
