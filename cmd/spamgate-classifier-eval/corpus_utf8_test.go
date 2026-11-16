package main

import (
 "bytes"
 "strings"
 "testing"
)

func TestCorpusRejectsInvalidUTF8WithoutReport(t *testing.T) {
 good:=[]byte(`[{"id":"clean","tenant":"alpha","spam":false,"score":0}]`)
 cases:=[][]byte{
  append(append([]byte(nil),good[:len(good)-2]...),0xff,']'),
  append([]byte{0xff},good...),
  append(append([]byte(nil),good...),0xc3),
 }
 for i,payload:=range cases {
  var out bytes.Buffer
  err:=run(nil,bytes.NewReader(payload),&out)
  if err==nil||!strings.Contains(err.Error(),"invalid UTF-8"){t.Errorf("case %d: expected invalid UTF-8 rejection, got %v",i,err)}
  if out.Len()!=0{t.Errorf("case %d: unexpected report emitted",i)}
 }
 var out bytes.Buffer
 if err:=run(nil,bytes.NewReader(good),&out);err!=nil{t.Fatalf("valid UTF-8 rejected: %v",err)}
 if out.Len()==0{t.Fatal("valid corpus produced no report")}
}
