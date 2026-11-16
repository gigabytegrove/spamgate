package main

import (
 "bytes"
 "strings"
 "testing"
)

func TestExpectedTenantQualificationRequiresBalancedEvidence(t *testing.T) {
 cases:=[]struct{name, corpus string; args []string; pass bool}{
  {"sufficient per tenant",`[{"id":"a","tenant":"alpha","spam":false,"score":0},{"id":"b","tenant":"alpha","spam":true,"score":8},{"id":"c","tenant":"beta","spam":false,"score":0},{"id":"d","tenant":"beta","spam":true,"score":8}]`,[]string{"-expected-tenants=alpha,beta","-max-fp-upper=1","-min-clean=1","-min-spam=1"},true},
  {"tenant without spam",`[{"id":"a","tenant":"alpha","spam":false,"score":0},{"id":"b","tenant":"beta","spam":false,"score":0},{"id":"c","tenant":"beta","spam":true,"score":8}]`,[]string{"-expected-tenants=alpha,beta","-max-fp-upper=1","-min-clean=1","-min-spam=1"},false},
  {"tenant without clean",`[{"id":"a","tenant":"alpha","spam":true,"score":8},{"id":"b","tenant":"beta","spam":false,"score":0},{"id":"c","tenant":"beta","spam":true,"score":8}]`,[]string{"-expected-tenants=alpha,beta","-max-fp-upper=1","-min-clean=1","-min-spam=1"},false},
  {"exploration unaffected",`[{"id":"a","tenant":"alpha","spam":false,"score":0}]`,[]string{"-expected-tenants=alpha"},true},
 }
 for _,tc:=range cases {t.Run(tc.name,func(t *testing.T){
  var out bytes.Buffer
  err:=run(tc.args,strings.NewReader(tc.corpus),&out)
  if (err==nil)!=tc.pass {t.Fatalf("pass=%v err=%v output=%s",tc.pass,err,out.String())}
  if !tc.pass&&out.Len()!=0 {t.Fatalf("failed evidence emitted report: %s",out.String())}
 })}
}
