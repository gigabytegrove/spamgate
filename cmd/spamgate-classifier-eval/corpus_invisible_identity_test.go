package main

import (
 "strings"
 "testing"
)

func TestCorpusIdentityRejectsInvisibleAndNoncanonicalNames(t *testing.T) {
 cases:=[]struct{name,payload,want string}{
  {"id leading space",`[{"id":" a","tenant":"alpha","spam":false,"score":0}]`,"surrounding whitespace"},
  {"id trailing tab",`[{"id":"a\t","tenant":"alpha","spam":false,"score":0}]`,"surrounding whitespace"},
  {"tenant trailing space",`[{"id":"a","tenant":"alpha ","spam":false,"score":0}]`,"surrounding whitespace"},
  {"embedded newline",`[{"id":"a\nb","tenant":"alpha","spam":false,"score":0}]`,"control or format"},
  {"embedded null",`[{"id":"a\u0000b","tenant":"alpha","spam":false,"score":0}]`,"control or format"},
  {"zero width joiner",`[{"id":"a\u200db","tenant":"alpha","spam":false,"score":0}]`,"control or format"},
  {"tenant bidi override",`[{"id":"a","tenant":"a\u202eb","spam":false,"score":0}]`,"control or format"},
  {"ordinary unicode",`[{"id":"é-1","tenant":"équipe","spam":false,"score":0}]`,""},
  {"interior space",`[{"id":"sample 1","tenant":"tenant one","spam":false,"score":0}]`,""},
 }
 for _,tc:=range cases {t.Run(tc.name,func(t *testing.T){
  payload:=[]byte(tc.payload)
  if err:=rejectDuplicateJSONKeys(payload);err!=nil {t.Fatalf("JSON integrity: %v",err)}
  err:=validateCorpusSchema(payload)
  if tc.want=="" {if err!=nil {t.Fatalf("valid identity rejected: %v",err)};return}
  if err==nil||!strings.Contains(err.Error(),tc.want){t.Fatalf("wanted %q; got %v",tc.want,err)}
 })}
}

func TestCorpusInvisibleIdentityFailsWithoutReport(t *testing.T){
 var out strings.Builder
 err:=run(nil,strings.NewReader(`[{"id":"a\u200db","tenant":"alpha","spam":false,"score":0}]`),&out)
 if err==nil||!strings.Contains(err.Error(),"control or format"){t.Fatalf("expected rejection: %v",err)}
 if out.Len()!=0 {t.Fatalf("invalid evidence produced report: %q",out.String())}
}
