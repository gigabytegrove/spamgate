package main

import (
 "strings"
 "testing"
)

func TestCorpusIdentityIntegrity(t *testing.T) {
 cases:=[]struct{name,payload,want string}{
  {"duplicate across tenants",`[{"id":"same","tenant":"a","spam":false,"score":0},{"id":"same","tenant":"b","spam":true,"score":7}]`,"duplicate sample id"},
  {"duplicate escaped id",`[{"id":"A","tenant":"a","spam":false,"score":0},{"id":"\\u0041","tenant":"a","spam":true,"score":7}]`,"duplicate sample id"},
  {"empty id",`[{"id":"","tenant":"a","spam":false,"score":0}]`,"id must not be empty"},
  {"whitespace id",`[{"id":"  ","tenant":"a","spam":false,"score":0}]`,"id must not be empty"},
  {"empty tenant",`[{"id":"a","tenant":"","spam":false,"score":0}]`,"tenant must not be empty"},
  {"whitespace tenant",`[{"id":"a","tenant":"  ","spam":false,"score":0}]`,"tenant must not be empty"},
  {"distinct IDs",`[{"id":"A","tenant":"a","spam":false,"score":0},{"id":"a","tenant":"b","spam":true,"score":7}]`,""},
  {"valid zero",`[{"id":"a","tenant":"a","spam":false,"score":0}]`,""},
 }
 for _,tc:=range cases {
  t.Run(tc.name,func(t *testing.T){
   if err:=rejectDuplicateJSONKeys([]byte(tc.payload));err!=nil {t.Fatalf("JSON syntax: %v",err)}
   err:=validateCorpusSchema([]byte(tc.payload))
   if tc.want=="" {if err!=nil {t.Fatalf("unexpected rejection: %v",err)};return}
   if err==nil||!strings.Contains(err.Error(),tc.want){t.Fatalf("expected %q, got %v",tc.want,err)}
  })
 }
}

func TestCorpusIdentityFailureDoesNotWriteReport(t *testing.T) {
 payload:=`[{"id":"a","tenant":"one","spam":false,"score":0},{"id":"a","tenant":"one","spam":true,"score":10}]`
 var out strings.Builder
 err:=run(nil,strings.NewReader(payload),&out)
 if err==nil||!strings.Contains(err.Error(),"duplicate sample id"){t.Fatalf("expected duplicate rejection: %v",err)}
 if out.Len()!=0 {t.Fatalf("qualification report emitted for invalid corpus: %q",out.String())}
}
