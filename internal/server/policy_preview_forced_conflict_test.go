package server

import (
 "testing"

 "github.com/gigabytegrove/spamgate/internal/core"
)

// A forced rule trace that disagrees with the final verdict cannot be used
// as evidence for a hypothetical SMTP action. This is deliberately fail closed.
func TestPolicyPreviewConflictingForcedEvidenceIsIndeterminate(t *testing.T) {
 p := policyPreviewRequest{TagThreshold:4,QuarantineThreshold:8,RejectThreshold:15,Limit:10}
 for _,tc:=range []struct{name, historical, forced string; wantIndeterminate bool}{
  {"matching_reject","reject","reject",false},
  {"matching_tempfail","soft_reject","soft_reject",false},
  {"conflicting_reject","accept","reject",true},
  {"conflicting_tempfail","reject","soft_reject",true},
  {"conflicting_accept","quarantine","accept",true},
  {"no_forced_trace","tag","",false},
 } {
  t.Run(tc.name,func(t *testing.T){
   m:=core.Message{ID:"history",Score:6,Action:tc.historical,Scoring:&core.ScoringTrace{ForcedAction:tc.forced}}
   got:=previewOne(m,p,nil)
   if got.Indeterminate!=tc.wantIndeterminate {t.Fatalf("indeterminate=%v, want %v: %+v",got.Indeterminate,tc.wantIndeterminate,got)}
   if tc.wantIndeterminate {
    if got.HypotheticalAction!="" || got.Changed || got.Forced {t.Fatalf("conflicting trace produced a verdict: %+v",got)}
    totals:=policyPreviewTotals{}
    accumulatePolicyPreview(&totals,got)
    if totals.Determinate!=0 || totals.Changed!=0 || totals.Transitions!=nil {t.Fatalf("conflicting evidence counted: %+v",totals)}
   } else if tc.forced!="" && (!got.Forced || got.HypotheticalAction!=tc.forced) {
    t.Fatalf("matching forced verdict not preserved: %+v",got)
   }
  })
 }
}

func TestPolicyPreviewConflictingForcedEvidenceDoesNotPolluteTotals(t *testing.T) {
 p:=policyPreviewRequest{TagThreshold:4,QuarantineThreshold:8,RejectThreshold:15,Limit:10}
 messages:=[]core.Message{
  {ID:"conflict",Score:6,Action:"accept",Scoring:&core.ScoringTrace{ForcedAction:"reject"}},
  {ID:"consistent",Score:6,Action:"tag",Scoring:&core.ScoringTrace{ForcedAction:"tag"}},
 }
 totals:=policyPreviewTotals{}
 for _,m:=range messages {
  item:=previewOne(m,p,nil)
  totals.Examined++
  if item.Indeterminate {totals.Indeterminate++}
  accumulatePolicyPreview(&totals,item)
 }
 if totals.Examined!=2 || totals.Determinate!=1 || totals.Indeterminate!=1 || totals.Transitions["tag"]["tag"]!=1 || totals.Changed!=0 {
  t.Fatalf("bad mixed-evidence accounting: %+v",totals)
 }
}
