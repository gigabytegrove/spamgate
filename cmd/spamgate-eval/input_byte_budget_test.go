package main

import (
 "bytes"
 "strings"
 "testing"
)

func TestCorpusByteBudgetExactAndOverflow(t *testing.T) {
 data := []byte("{\"label\":\"ham\",\"action\":\"accept\"}\n{\"label\":\"spam\",\"action\":\"reject\"}\n")
 c,_,_,err:=readLabelledCorpusWithBudgets(bytes.NewReader(data),false,2,int64(len(data)))
 if err!=nil || c.Ham!=1 || c.Spam!=1 {t.Fatalf("exact budget: counts=%+v err=%v",c,err)}
 c,cohorts,unspecified,err:=readLabelledCorpusWithBudgets(bytes.NewReader(data),false,2,int64(len(data)-1))
 if err==nil || !strings.Contains(err.Error(),"input bytes") {t.Fatalf("expected byte-budget failure: %+v %v",c,err)}
 if c.Ham!=0 || c.Spam!=0 || cohorts!=nil || unspecified!=0 {t.Fatalf("partial results escaped: %+v %+v %d",c,cohorts,unspecified)}
}

func TestCorpusByteBudgetCountsBlankInput(t *testing.T) {
 records := "{\"label\":\"ham\",\"action\":\"accept\"}\n{\"label\":\"spam\",\"action\":\"reject\"}\n"
 data:=records+strings.Repeat("\n",1024)
 _,_,_,err:=readLabelledCorpusWithBudgets(strings.NewReader(data),false,2,int64(len(records)+10))
 if err==nil || !strings.Contains(err.Error(),"input bytes"){t.Fatalf("blank-line amplification escaped: %v",err)}
}

func TestCorpusByteBudgetValidation(t *testing.T) {
 for _,n:=range []int64{-1,0,9223372036854775807}{
  _,_,_,err:=readLabelledCorpusWithBudgets(strings.NewReader(""),false,1,n)
  if err==nil{t.Fatalf("accepted invalid byte budget %d",n)}
 }
}

func TestCorpusByteBudgetRejectsMalformedOversizedInput(t *testing.T) {
 data:=strings.Repeat(" ",100)+"{"
 _,_,_,err:=readLabelledCorpusWithBudgets(strings.NewReader(data),false,2,20)
 if err==nil{t.Fatal("oversized malformed input accepted")}
}
