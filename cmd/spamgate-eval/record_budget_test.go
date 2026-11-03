package main

import (
 "strings"
 "testing"
)

func TestCorpusRecordBudgetRejectsBeforeCountingExtraExamples(t *testing.T) {
 data := strings.Join([]string{
  `{"label":"ham","action":"accept","id":"`+strings.Repeat("a",64)+`"}`,
  `{"label":"spam","action":"reject","id":"`+strings.Repeat("b",64)+`"}`,
  `{"label":"ham","action":"accept","id":"`+strings.Repeat("c",64)+`"}`,
 },"\n")
 c,_,_,err:=readLabelledCorpusWithLimit(strings.NewReader(data),true,2)
 if err==nil || !strings.Contains(err.Error(),"exceeds maximum"){t.Fatalf("expected bounded corpus error; counts=%+v err=%v",c,err)}
 if c.Ham!=0 || c.Spam!=0 {t.Fatalf("partial counts escaped on failure: %+v",c)}
 c,_,_,err=readLabelledCorpusWithLimit(strings.NewReader(data),true,3)
 if err!=nil || c.Ham!=2 || c.Spam!=1 {t.Fatalf("exact-budget corpus failed: %+v %v",c,err)}
}

func TestCorpusRecordBudgetIgnoresBlankLinesAndRejectsInvalidLimit(t *testing.T) {
 data:="\n"+`{"label":"ham","action":"accept"}`+"\n\n"+`{"label":"spam","action":"reject"}`+"\n"
 c,_,_,err:=readLabelledCorpusWithLimit(strings.NewReader(data),false,2)
 if err!=nil || c.Ham!=1 || c.Spam!=1 {t.Fatalf("blank lines counted toward budget: %+v %v",c,err)}
 _,_,_,err=readLabelledCorpusWithLimit(strings.NewReader(data),false,0)
 if err==nil {t.Fatal("zero record budget accepted")}
}
