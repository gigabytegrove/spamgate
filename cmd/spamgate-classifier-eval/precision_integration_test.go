package main

import (
 "bytes"
 "strings"
 "testing"
)

func TestPrecisionCLIQualificationFailureAndSuccess(t *testing.T){
 corpus:=`[{"id":"s1","tenant":"alpha","spam":true,"score":9},{"id":"s2","tenant":"alpha","spam":false,"score":9}]`
 for _,tc:=range []struct{args []string; fail bool}{
  {[]string{"-min-precision=0.8","-min-predicted-spam=1"},true},
  {[]string{"-min-precision=0","-min-predicted-spam=1"},false},
  {[]string{"-min-precision=0","-min-predicted-spam=3"},true},
 }{
  var out bytes.Buffer
  err:=run(tc.args,strings.NewReader(corpus),&out)
  if (err!=nil)!=tc.fail{t.Fatalf("args %v: err=%v output=%s",tc.args,err,out.String())}
  if !strings.Contains(out.String(),`"precision_gates"`){t.Fatalf("missing structured gate evidence: %s",out.String())}
 }
}
func TestPrecisionCLIInvalidGate(t *testing.T){
 corpus:=`[{"id":"s1","tenant":"alpha","spam":true,"score":9}]`
 if err:=run([]string{"-min-precision=0.8","-min-predicted-spam=0"},strings.NewReader(corpus),&bytes.Buffer{});err==nil{t.Fatal("invalid minimum must fail")}
}
