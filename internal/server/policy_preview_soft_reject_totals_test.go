package server

import (
 "encoding/json"
 "testing"

 "github.com/gigabytegrove/spamgate/internal/core"
)

func TestPolicyPreviewTemporaryRejectionTotals(t *testing.T) {
 p := policyPreviewRequest{TagThreshold:4,QuarantineThreshold:8,RejectThreshold:15,Limit:20}
 messages := []core.Message{
  {ID:"temporary",Score:10,Action:"soft_reject",Scoring:&core.ScoringTrace{ForcedAction:"soft_reject"}},
  {ID:"permanent",Score:20,Action:"reject"},
  {ID:"accepted",Score:0,Action:"accept"},
 }
 totals := policyPreviewTotals{}
 for _, m := range messages {
  item := previewOne(m,p,nil)
  if item.Indeterminate { t.Fatalf("unexpected indeterminate result: %+v",item) }
  totals.Examined++
  accumulatePolicyPreview(&totals,item)
 }
 if totals.WouldSoftReject!=1 || totals.WouldReject!=1 || totals.WouldAccept!=1 || totals.ForcedPreserved!=1 || totals.Changed!=0 {
  t.Fatalf("temporary rejection conflated with permanent rejection: %+v",totals)
 }
 encoded,err:=json.Marshal(totals)
 if err!=nil {t.Fatal(err)}
 var result struct {
  WouldSoftReject int `json:"would_soft_reject"`
  WouldReject int `json:"would_reject"`
 }
 if err:=json.Unmarshal(encoded,&result);err!=nil {t.Fatal(err)}
 if result.WouldSoftReject!=1 || result.WouldReject!=1 {
  t.Fatalf("missing distinct JSON counters: %s",encoded)
 }
}

func TestPolicyPreviewInvalidEvidenceNeverContributesTotals(t *testing.T) {
 totals:=policyPreviewTotals{Examined:1,Indeterminate:1}
 accumulatePolicyPreview(&totals,policyPreviewItem{Indeterminate:true,Forced:true,Changed:true,HypotheticalAction:"soft_reject",PolicySource:"mailbox_shared"})
 if totals.WouldSoftReject!=0 || totals.Changed!=0 || totals.ForcedPreserved!=0 || totals.UniformShared!=0 {
  t.Fatalf("indeterminate evidence changed totals: %+v",totals)
 }
}
