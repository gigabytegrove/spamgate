package transport

import (
 "errors"
 "math"
 "testing"

 "github.com/gigabytegrove/spamgate/internal/core"
)

func TestRspamdScanResultFiniteGate(t *testing.T) {
 base := core.DefaultConfig()
 cases := []struct {
  name string
  mutate func(*core.Message, *core.Config)
  bad bool
 }{
  {"ordinary finite result",func(*core.Message,*core.Config){},false},
  {"score NaN",func(m *core.Message,_ *core.Config){m.Score=math.NaN()},true},
  {"score positive infinity",func(m *core.Message,_ *core.Config){m.Score=math.Inf(1)},true},
  {"score negative infinity",func(m *core.Message,_ *core.Config){m.Score=math.Inf(-1)},true},
  {"finding NaN",func(m *core.Message,_ *core.Config){m.Findings=[]core.Finding{{Symbol:"TEST",Score:math.NaN()}}},true},
  {"finding infinity",func(m *core.Message,_ *core.Config){m.Findings=[]core.Finding{{Symbol:"TEST",Score:math.Inf(1)}}},true},
  {"tag threshold NaN",func(_ *core.Message,c *core.Config){c.Settings.TagThreshold=math.NaN()},true},
  {"quarantine threshold infinity",func(_ *core.Message,c *core.Config){c.Settings.QuarantineThreshold=math.Inf(1)},true},
  {"reject threshold NaN",func(_ *core.Message,c *core.Config){c.Settings.RejectThreshold=math.NaN()},true},
  {"trace tag NaN",func(m *core.Message,_ *core.Config){m.Scoring=&core.ScoringTrace{TagThreshold:math.NaN()}},true},
  {"trace quarantine infinity",func(m *core.Message,_ *core.Config){m.Scoring=&core.ScoringTrace{QuarantineThreshold:math.Inf(-1)}},true},
  {"trace reject NaN",func(m *core.Message,_ *core.Config){m.Scoring=&core.ScoringTrace{RejectThreshold:math.NaN()}},true},
 }
 for _,tc:=range cases {
  t.Run(tc.name,func(t *testing.T){
   m:=core.Message{Action:"accept",Score:2,Findings:[]core.Finding{{Symbol:"SAFE",Score:1}}}
   c:=base
   tc.mutate(&m,&c)
   err:=rspamdValidateScanResult(m,c)
   if (err!=nil)!=tc.bad {t.Fatalf("error=%v wantBad=%v",err,tc.bad)}
   if tc.bad && !errors.Is(err,errRspamdInvalidScanResult){t.Fatalf("wrong error: %v",err)}
  })
 }
}
