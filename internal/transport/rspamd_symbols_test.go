package transport

import (
 "errors"
 "math"
 "testing"

 "github.com/gigabytegrove/spamgate/internal/core"
)

func TestRspamdSymbolsAggregate(t *testing.T) {
 findings := []core.Finding{
  {Symbol:"RULE_A",Score:1.25,Detail:"first",Source:"header"},
  {Symbol:"RULE_A",Score:-0.25,Detail:"second",Source:"body"},
  {Symbol:"RULE_B",Score:2,Detail:"third",Source:"url"},
 }
 symbols, err := rspamdSymbols(findings)
 if err != nil { t.Fatal(err) }
 if len(symbols)!=2 { t.Fatalf("symbols=%d, want 2",len(symbols)) }
 a:=symbols["RULE_A"]
 if a["score"].(float64)!=1 { t.Fatalf("score=%v, want 1",a["score"]) }
 opts:=a["options"].([]string)
 if len(opts)!=2 || opts[0]!="first" || opts[1]!="second" { t.Fatalf("options=%v",opts) }
 if a["description"]!="header" { t.Fatalf("description=%v",a["description"]) }
}

func TestRspamdSymbolsRejectOverflow(t *testing.T) {
 cases:=[]struct{name string; findings []core.Finding}{
  {"positive overflow",[]core.Finding{{Symbol:"A",Score:math.MaxFloat64},{Symbol:"A",Score:math.MaxFloat64}}},
  {"negative overflow",[]core.Finding{{Symbol:"A",Score:-math.MaxFloat64},{Symbol:"A",Score:-math.MaxFloat64}}},
  {"nonfinite single",[]core.Finding{{Symbol:"A",Score:math.NaN()}}},
  {"infinite single",[]core.Finding{{Symbol:"A",Score:math.Inf(1)}}},
 }
 for _,tc:=range cases {
  t.Run(tc.name,func(t *testing.T){
   result,err:=rspamdSymbols(tc.findings)
   if !errors.Is(err,errRspamdSymbolOverflow){t.Fatalf("err=%v, want overflow",err)}
   if result!=nil {t.Fatalf("partial result returned: %v",result)}
  })
 }
}

func TestRspamdSymbolsDistinctLargeFiniteScores(t *testing.T) {
 symbols,err:=rspamdSymbols([]core.Finding{{Symbol:"A",Score:math.MaxFloat64},{Symbol:"B",Score:math.MaxFloat64}})
 if err!=nil {t.Fatal(err)}
 if len(symbols)!=2 {t.Fatalf("symbols=%d",len(symbols))}
}
