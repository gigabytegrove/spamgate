package main

import (
 "bytes"
 "strings"
 "testing"
)

func TestCorpusRejectsCaseFoldedEvidenceAliases(t *testing.T) {
 cases:=[]struct{name,corpus string;pass bool}{
  {"duplicate spam alias",`[{"id":"a","tenant":"alpha","spam":true,"Spam":false,"score":8}]`,false},
  {"duplicate score alias",`[{"id":"a","tenant":"alpha","spam":true,"score":8,"Score":0}]`,false},
  {"escaped alias",`[{"id":"a","tenant":"alpha","spam":true,"s\\u0063ore":8,"SCORE":0}]`,false},
  {"unknown evidence",`[{"id":"a","tenant":"alpha","spam":true,"score":8,"untrusted":1}]`,false},
  {"valid exact schema",`[{"id":"a","tenant":"alpha","spam":true,"score":8}]`,true},
 }
 for _,tc:=range cases {t.Run(tc.name,func(t *testing.T){
  var out bytes.Buffer
  err:=run(nil,strings.NewReader(tc.corpus),&out)
  if (err==nil)!=tc.pass {t.Fatalf("pass=%v error=%v output=%s",tc.pass,err,out.String())}
  if !tc.pass&&out.Len()!=0 {t.Fatalf("rejected corpus emitted report: %s",out.String())}
 })}
}
