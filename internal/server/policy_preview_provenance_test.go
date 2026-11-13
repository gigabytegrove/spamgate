package server

import (
 "encoding/json"
 "math"
 "testing"

 "github.com/gigabytegrove/spamgate/internal/core"
)

func TestPolicyPreviewScoreProvenance(t *testing.T) {
 p:=policyPreviewRequest{TagThreshold:4,QuarantineThreshold:8,RejectThreshold:15,Limit:10}
 for _,tc:=range []struct{name string; score float64; valid bool}{
  {"zero",0,true},{"negative",-1,false},{"overflow",1001,false},
  {"nan",math.NaN(),false},{"positive_infinity",math.Inf(1),false},{"negative_infinity",math.Inf(-1),false},
 } {
  t.Run(tc.name,func(t *testing.T){
   item:=previewOne(core.Message{ID:tc.name,Score:tc.score,Action:"accept"},p,nil)
   if item.ScoreValid!=tc.valid || item.Indeterminate==tc.valid {t.Fatalf("score provenance mismatch: %+v",item)}
   b,err:=json.Marshal(item);if err!=nil {t.Fatal(err)}
   var decoded struct{Score float64 `json:"score"`; ScoreValid bool `json:"score_valid"`}
   if err:=json.Unmarshal(b,&decoded);err!=nil {t.Fatal(err)}
   if decoded.ScoreValid!=tc.valid {t.Fatalf("serialized score provenance: %s",b)}
   if !tc.valid && decoded.Score!=0 {t.Fatalf("invalid score must serialize safely: %s",b)}
  })
 }
}

func TestPolicyPreviewCoveragePercent(t *testing.T) {
 for _,tc:=range []struct{examined,total int; want float64}{
  {0,0,100},{0,10,0},{5,10,50},{1,4,25},{10,10,100},
  {12,10,100},{-1,10,0},{1,-1,0},
 }{
  got:=previewCoveragePercent(tc.examined,tc.total)
  if got!=tc.want {t.Errorf("coverage(%d,%d)=%v want %v",tc.examined,tc.total,got,tc.want)}
 }
}
