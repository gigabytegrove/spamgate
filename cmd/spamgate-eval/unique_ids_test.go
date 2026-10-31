package main

import (
 "bytes"
 "encoding/json"
 "os"
 "strings"
 "testing"
)

func TestStrictUniqueIDsRejectsRepeatedCorpus(t *testing.T) {
 a:=strings.Repeat("a",64)
 b:=strings.Repeat("b",64)
 valid:=strings.Join([]string{
  `{"label":"ham","action":"accept","cohort":"direct","id":"`+a+`"}`,
  `{"label":"spam","action":"reject","cohort":"forwarded","id":"`+b+`"}`,
 },"\n")
 if _,_,_,err:=readLabelledCorpusWithOptions(strings.NewReader(valid),true);err!=nil{t.Fatalf("valid strict corpus: %v",err)}
 for name,corpus:=range map[string]string{
  "duplicate same cohort":valid+"\n"+`{"label":"ham","action":"accept","cohort":"direct","id":"`+a+`"}`,
  "duplicate across cohorts":valid+"\n"+`{"label":"spam","action":"reject","cohort":"attachment","id":"`+a+`"}`,
  "missing id":strings.Replace(valid,`,"id":"`+a+`"`,"",1),
  "uppercase":strings.Replace(valid,a,strings.ToUpper(a),1),
  "short":strings.Replace(valid,a,"a",1),
  "invalid hex":strings.Replace(valid,a,strings.Repeat("z",64),1),
 }{
  if _,_,_,err:=readLabelledCorpusWithOptions(strings.NewReader(corpus),true);err==nil{
   t.Fatalf("%s accepted as strict corpus",name)
  }
 }
}

func TestOptionalIDsStillRejectDuplicates(t *testing.T) {
 a:=strings.Repeat("a",64)
 corpus:=`{"label":"ham","action":"accept","id":"`+a+`"}`+"\n"+
  `{"label":"spam","action":"reject","id":"`+a+`"}`
 if _,_,_,err:=readLabelledCorpus(strings.NewReader(corpus));err==nil{
  t.Fatal("duplicate explicitly supplied ID accepted")
 }
 legacy:=`{"label":"ham","action":"accept"}`+"\n"+`{"label":"spam","action":"reject"}`
 if _,_,_,err:=readLabelledCorpus(strings.NewReader(legacy));err!=nil{
  t.Fatalf("legacy corpus broken: %v",err)
 }
}

func TestStrictUniqueIDsCLI(t *testing.T) {
 a:=strings.Repeat("a",64)
 b:=strings.Repeat("b",64)
 dir:=t.TempDir()
 path:=dir+"/labels.jsonl"
 corpus:=`{"label":"ham","action":"accept","id":"`+a+`"}`+"\n"+
  `{"label":"spam","action":"reject","id":"`+b+`"}`+"\n"
 if err:=os.WriteFile(path,[]byte(corpus),0600);err!=nil{t.Fatal(err)}
 var out,errOut bytes.Buffer
 args:=[]string{"--require-unique-ids","--min-ham=1","--min-spam=1","--max-fpr-upper=1","--min-recall-lower=0",path}
 if code:=run(args,&out,&errOut);code!=0{t.Fatalf("strict CLI failed: code=%d %s",code,errOut.String())}
 var result map[string]any
 if err:=json.Unmarshal(out.Bytes(),&result);err!=nil{t.Fatal(err)}
 if result["gate_passed"]!=true{t.Fatalf("unexpected strict result: %v",result)}
}
