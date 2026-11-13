package server

import (
 "encoding/json"
 "math"
 "testing"

 "github.com/gigabytegrove/spamgate/internal/core"
)

func TestPolicyPreviewScoreBoundsAndJSON(t *testing.T) {
 p:=policyPreviewRequest{TagThreshold:4,QuarantineThreshold:8,RejectThreshold:15,Limit:20}
 cases:=[]struct{name string;score float64;indeterminate bool}{
  {"negative",-0.001,true},
  {"below_zero_infinity",math.Inf(-1),true},
  {"above_max",1000.001,true},
  {"positive_infinity",math.Inf(1),true},
  {"nan",math.NaN(),true},
  {"zero",0,false},
  {"maximum",1000,false},
 }
 for _,tc:=range cases {
  t.Run(tc.name,func(t *testing.T){
   item:=previewOne(core.Message{ID:tc.name,Score:tc.score,Action:"tag"},p,nil)
   if item.Indeterminate!=tc.indeterminate {t.Fatalf("indeterminate=%v expected=%v: %+v",item.Indeterminate,tc.indeterminate,item)}
   if tc.indeterminate && (item.Changed || item.HypotheticalAction!="" || item.Note=="") {t.Fatalf("invalid historical score trusted: %+v",item)}
   if _,err:=json.Marshal(item);err!=nil {t.Fatalf("preview JSON invalid: %v",err)}
  })
 }
}

func TestPolicyPreviewInvalidScoreDoesNotTrustForcedVerdict(t *testing.T) {
 p:=policyPreviewRequest{TagThreshold:4,QuarantineThreshold:8,RejectThreshold:15,Limit:20}
 item:=previewOne(core.Message{ID:"corrupt",Score:-10,Action:"tag",Scoring:&core.ScoringTrace{ForcedAction:"reject"}},p,nil)
 if !item.Indeterminate || item.Forced || item.HypotheticalAction!="" {t.Fatalf("forced verdict trusted despite invalid score: %+v",item)}
}
