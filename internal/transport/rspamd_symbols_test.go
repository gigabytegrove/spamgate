package transport

import (
 "errors"
 "math"
 "strings"
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

func TestRspamdSymbolsRejectInvalidMetadata(t *testing.T) {
 cases:=[]struct{name string; finding core.Finding}{
  {"empty symbol",core.Finding{Symbol:""}},
  {"newline symbol",core.Finding{Symbol:"SAFE\nINJECT"}},
  {"punctuation symbol",core.Finding{Symbol:"RULE.NAME"}},
  {"leading underscore",core.Finding{Symbol:"_RULE"}},
  {"oversized symbol",core.Finding{Symbol:strings.Repeat("A",rspamdMaxSymbolBytes+1)}},
  {"newline detail",core.Finding{Symbol:"RULE",Detail:"hello\r\nworld"}},
  {"oversized detail",core.Finding{Symbol:"RULE",Detail:strings.Repeat("x",rspamdMaxDetailBytes+1)}},
  {"control source",core.Finding{Symbol:"RULE",Source:"source\x00"}},
  {"oversized source",core.Finding{Symbol:"RULE",Source:strings.Repeat("x",rspamdMaxSourceBytes+1)}},
  {"invalid UTF8",core.Finding{Symbol:"RULE",Detail:string([]byte{0xff})}},
 }
 for _,tc:=range cases {
  t.Run(tc.name,func(t *testing.T){
   got,err:=rspamdSymbols([]core.Finding{{Symbol:"GOOD",Score:1},tc.finding})
   if !errors.Is(err,errRspamdSymbolMetadata) {t.Fatalf("err=%v",err)}
   if got!=nil {t.Fatalf("partial symbols returned: %v",got)}
  })
 }
}

func TestRspamdSymbolsFindingLimit(t *testing.T) {
 findings:=make([]core.Finding,rspamdMaxFindings+1)
 for i:=range findings { findings[i].Symbol="RULE" }
 got,err:=rspamdSymbols(findings)
 if !errors.Is(err,errRspamdSymbolMetadata)||got!=nil {t.Fatalf("result=%v err=%v",got,err)}
}

func TestRspamdSymbolsBoundaries(t *testing.T) {
 f:=core.Finding{Symbol:strings.Repeat("A",rspamdMaxSymbolBytes),Detail:strings.Repeat("x",rspamdMaxDetailBytes),Source:strings.Repeat("s",rspamdMaxSourceBytes)}
 result,err:=rspamdSymbols([]core.Finding{f})
 if err!=nil||len(result)!=1 {t.Fatalf("result=%v err=%v",result,err)}
}

func TestRspamdSymbolsAggregateMetadataBudget(t *testing.T) {
 within := make([]core.Finding, 256)
 for i := range within {
  within[i] = core.Finding{Symbol:"RULE", Detail:strings.Repeat("x", 4090)}
 }
 result,err:=rspamdSymbols(within)
 if err!=nil || len(result)!=1 {t.Fatalf("within budget: result=%d err=%v",len(result),err)}
 exceeded:=append(within,core.Finding{Symbol:"RULE",Detail:strings.Repeat("y",4090)})
 got,err:=rspamdSymbols(exceeded)
 if !errors.Is(err,errRspamdSymbolMetadata) || got!=nil {t.Fatalf("over budget: result=%v err=%v",got,err)}
}
