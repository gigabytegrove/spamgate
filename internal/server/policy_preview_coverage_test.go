package server

import (
 "encoding/json"
 "testing"

 "github.com/gigabytegrove/spamgate/internal/core"
)

func TestPolicyPreviewHistoricalDispositionAccounting(t *testing.T) {
 p := policyPreviewRequest{TagThreshold:4,QuarantineThreshold:8,RejectThreshold:15,Limit:20}
 cases := []struct{ action string; score float64 }{
  {"accept",0},{"tag",4},{"quarantine",8},{"reject",15},{"soft_reject",10},
 }
 totals:=policyPreviewTotals{}
 for _,tc:=range cases {
  item:=previewOne(core.Message{Action:tc.action,Score:tc.score},p,nil)
  if item.Indeterminate {t.Fatalf("unexpected indeterminate: %+v",item)}
  totals.Examined++
  accumulatePolicyPreview(&totals,item)
 }
 if totals.Determinate!=5 || totals.HistoricalAccept!=1 || totals.HistoricalTag!=1 ||
 totals.HistoricalQuarantine!=1 || totals.HistoricalReject!=1 || totals.HistoricalSoftReject!=1 ||
 totals.WouldAccept!=1 || totals.WouldTag!=1 || totals.WouldQuarantine!=2 || totals.WouldReject!=1 ||
 totals.Changed!=1 {
  t.Fatalf("disposition accounting mismatch: %+v",totals)
 }
 encoded,err:=json.Marshal(totals)
 if err!=nil {t.Fatal(err)}
 var decoded struct {
  Determinate int `json:"determinate"`
  HistoricalSoftReject int `json:"historical_soft_reject"`
 }
 if err:=json.Unmarshal(encoded,&decoded);err!=nil {t.Fatal(err)}
 if decoded.Determinate!=5 || decoded.HistoricalSoftReject!=1 {t.Fatalf("missing JSON evidence: %s",encoded)}
}

func TestPolicyPreviewIndeterminateExcludedFromHistoricalCounters(t *testing.T) {
 totals:=policyPreviewTotals{Examined:2,Indeterminate:2}
 for _,item:=range []policyPreviewItem{
  {Indeterminate:true,HistoricalAction:"reject",HypotheticalAction:"accept",Changed:true},
  {Indeterminate:true,HistoricalAction:"soft_reject",HypotheticalAction:"soft_reject",Forced:true},
 } {accumulatePolicyPreview(&totals,item)}
 if totals.Determinate!=0 || totals.HistoricalReject!=0 || totals.HistoricalSoftReject!=0 ||
 totals.Changed!=0 || totals.ForcedPreserved!=0 {t.Fatalf("corrupt history counted: %+v",totals)}
}
