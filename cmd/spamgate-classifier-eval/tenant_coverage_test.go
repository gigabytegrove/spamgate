package main

import (
 "bytes"
 "strings"
 "testing"
)

func TestTenantCoverageGate(t *testing.T) {
 corpus:=`[{"id":"a","tenant":"alpha","spam":false,"score":0},{"id":"b","tenant":"beta","spam":true,"score":8}]`
 cases:=[]struct{name,spec string;pass bool}{
  {"exact","alpha,beta",true},
  {"order and whitespace"," beta , alpha ",true},
  {"omitted tenant","alpha",false},
  {"unknown tenant","alpha,beta,gamma",false},
  {"duplicate","alpha,alpha,beta",false},
  {"empty","alpha,,beta",false},
  {"trailing comma","alpha,beta,",false},
  {"case sensitive","Alpha,beta",false},
 }
 for _,tc:=range cases {t.Run(tc.name,func(t *testing.T){
  var out bytes.Buffer
  err:=run([]string{"-expected-tenants="+tc.spec},strings.NewReader(corpus),&out)
  if (err==nil)!=tc.pass {t.Fatalf("expected pass=%v got error=%v",tc.pass,err)}
  if !tc.pass && out.Len()!=0 {t.Fatalf("failure emitted report: %s",out.String())}
 })}
}
