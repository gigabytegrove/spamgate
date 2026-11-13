package server

import (
 "encoding/json"
 "testing"
)

func TestPolicyPreviewTransitionsCountAllDeterminatePairs(t *testing.T) {
 cases := []struct{ historical, candidate string; indeterminate bool }{
  {"accept","accept",false},
  {"accept","tag",false},
  {"tag","quarantine",false},
  {"quarantine","soft_reject",false},
  {"soft_reject","reject",false},
  {"reject","accept",false},
  {"reject","accept",true},
 }
 totals := policyPreviewTotals{}
 for _,tc := range cases {
  totals.Examined++
  if tc.indeterminate { totals.Indeterminate++ }
  accumulatePolicyPreview(&totals,policyPreviewItem{
   HistoricalAction:tc.historical,HypotheticalAction:tc.candidate,
   Changed:tc.historical!=tc.candidate,Indeterminate:tc.indeterminate,
  })
 }
 if totals.Determinate!=6 || totals.Indeterminate!=1 || totals.Changed!=5 {
  t.Fatalf("incorrect sample accounting: %+v",totals)
 }
 for _,tc:=range cases[:6] {
  if got:=totals.Transitions[tc.historical][tc.candidate];got!=1 {
   t.Fatalf("transition %s -> %s = %d, want 1",tc.historical,tc.candidate,got)
  }
 }
 if totals.Transitions["reject"]["accept"]!=1 {t.Fatal("indeterminate record counted")}
 raw,err:=json.Marshal(totals)
 if err!=nil {t.Fatal(err)}
 var decoded struct{ Transitions map[string]map[string]int `json:"transitions"` }
 if err:=json.Unmarshal(raw,&decoded);err!=nil {t.Fatal(err)}
 if decoded.Transitions["soft_reject"]["reject"]!=1 {t.Fatalf("missing serialized transition: %s",raw)}
}

func TestPolicyPreviewTransitionsNeverIncludeIndeterminate(t *testing.T) {
 totals:=policyPreviewTotals{}
 accumulatePolicyPreview(&totals,policyPreviewItem{HistoricalAction:"reject",HypotheticalAction:"accept",Indeterminate:true,Changed:true})
 if totals.Transitions!=nil || totals.Determinate!=0 || totals.Changed!=0 {
  t.Fatalf("indeterminate evidence contaminated transition matrix: %+v",totals)
 }
}
