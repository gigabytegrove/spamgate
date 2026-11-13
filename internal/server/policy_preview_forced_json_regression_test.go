package server

import (
 "encoding/json"
 "math"
 "testing"

 "github.com/gigabytegrove/spamgate/internal/core"
)

// This guards against source corruption in the forced-verdict path and ensures
// untrusted saved evidence cannot become a trusted simulated disposition.
func TestPolicyPreviewForcedEvidenceAndJSONSafety(t *testing.T) {
 p:=policyPreviewRequest{TagThreshold:4,QuarantineThreshold:8,RejectThreshold:15,Limit:10}
 cases:=[]struct{name string; score float64; historical,forced string; indeterminate bool}{
  {"matching",6,"tag","tag",false},
  {"conflict",6,"accept","reject",true},
  {"nan",math.NaN(),"accept","accept",true},
  {"infinity",math.Inf(1),"accept","accept",true},
  {"negative",-1,"accept","accept",true},
  {"overflow",1001,"accept","accept",true},
  {"invalid_final",6,"unknown","reject",true},
  {"invalid_forced",6,"accept","unknown",true},
 }
 for _,tc:=range cases {
  t.Run(tc.name,func(t *testing.T){
   item:=previewOne(core.Message{ID:tc.name,Score:tc.score,Action:tc.historical,Scoring:&core.ScoringTrace{ForcedAction:tc.forced}},p,nil)
   if item.Indeterminate!=tc.indeterminate {t.Fatalf("indeterminate=%v want %v: %+v",item.Indeterminate,tc.indeterminate,item)}
   if _,err:=json.Marshal(item);err!=nil {t.Fatalf("preview not JSON safe: %v",err)}
   totals:=policyPreviewTotals{}
   accumulatePolicyPreview(&totals,item)
   if tc.indeterminate {
    if totals.Determinate!=0 || totals.Transitions!=nil || item.HypotheticalAction!="" || item.Forced || item.Changed {t.Fatalf("invalid evidence counted: %+v %+v",item,totals)}
   } else if totals.Determinate!=1 || totals.ForcedPreserved!=1 || totals.Transitions["tag"]["tag"]!=1 {t.Fatalf("valid evidence lost: %+v %+v",item,totals)}
  })
 }
}
