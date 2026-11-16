package main

import (
 "bytes"
 "strings"
 "testing"
)
func TestCLI(t *testing.T){
 input:=`[{"id":"1","tenant":"alpha","spam":true,"score":7},{"id":"2","tenant":"alpha","spam":false,"score":2}]`
 var out bytes.Buffer
 if err:=run([]string{"-threshold","5"},strings.NewReader(input),&out);err!=nil{t.Fatal(err)}
 if !strings.Contains(out.String(),`"true_positive": 1`)||!strings.Contains(out.String(),`"true_negative": 1`){t.Fatal(out.String())}
}
func TestRejectUnknownAndTrailing(t *testing.T){
 for _,input:=range []string{`[{"id":"1","tenant":"a","spam":false,"score":1,"unknown":1}]`,`[] []`} {
  if err:=run(nil,strings.NewReader(input),&bytes.Buffer{});err==nil{t.Fatalf("accepted %s",input)}
 }
}
