package server

import (
 "encoding/json"
 "math"
 "testing"

 "github.com/gigabytegrove/spamgate/internal/core"
)

// Corrupt imported history must never silently become an accept or reject
// forecast, or poison the entire JSON response with NaN/Inf.
func TestPolicyPreviewCorruptHistoryIndeterminate(t *testing.T) {
 p := policyPreviewRequest{TagThreshold:4, QuarantineThreshold:8, RejectThreshold:15, Limit:20}
 cases := []struct{
  name string
  message core.Message
 }{
  {"nan",core.Message{ID:"nan",Score:math.NaN(),Action:"tag"}},
  {"positive_infinity",core.Message{ID:"inf",Score:math.Inf(1),Action:"tag"}},
  {"negative_infinity",core.Message{ID:"-inf",Score:math.Inf(-1),Action:"tag"}},
  {"unknown_historical_action",core.Message{ID:"unknown",Score:10,Action:"deleted"}},
  {"unknown_forced_action",core.Message{ID:"forced",Score:10,Action:"tag",Scoring:&core.ScoringTrace{ForcedAction:"discard"}}},
 }
 for _,tc := range cases {
  t.Run(tc.name,func(t *testing.T){
   item:=previewOne(tc.message,p,nil)
   if !item.Indeterminate || item.Changed || item.HypotheticalAction!="" || item.Note=="" {
    t.Fatalf("unsafe preview: %+v",item)
   }
   if _,err:=json.Marshal(item);err!=nil {t.Fatalf("invalid JSON response: %v",err)}
  })
 }
}

func TestPolicyPreviewKnownActionsAndValidForcedEvidence(t *testing.T) {
 for _,action:=range []string{"accept","tag","quarantine","reject","soft_reject"} {
  if !previewKnownAction(action) {t.Fatalf("missing supported action %q",action)}
 }
 for _,action:=range []string{"","discard","REJECT","reject\n"} {
  if previewKnownAction(action) {t.Fatalf("unsupported action trusted: %q",action)}
 }
 p:=policyPreviewRequest{TagThreshold:4,QuarantineThreshold:8,RejectThreshold:15,Limit:20}
 item:=previewOne(core.Message{ID:"valid",Score:5,Action:"tag",Scoring:&core.ScoringTrace{ForcedAction:"reject"}},p,nil)
 if item.Indeterminate || !item.Forced || item.HypotheticalAction!="reject" || !item.Changed {
  t.Fatalf("valid forced action lost: %+v",item)
 }
}
