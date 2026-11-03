package main

import (
 "fmt"
 "strings"
 "testing"
)

func TestAuditRejectsAmbiguousOrInvalidEvidence(t *testing.T) {
 cases := []string{
  `{"connector":"milter","action":"accept","action":"quarantine"}`,
  `{"connector":"milter","action":"accept","\u0061ction":"reject"}`,
  `{"connector":"milter","findings":{}}`,
  `{"connector":"milter","findings":"bad"}`,
  `{"connector":"milter","score":"0"}`,
  `[]`,
  `{"connector":"milter"} {"connector":"milter"}`,
 }
 for _, input := range cases {
  t.Run(input,func(t *testing.T){
   got,err:=analyze(strings.NewReader(input+"\n"))
   if err!=nil {t.Fatal(err)}
   if got.Malformed!=1 || got.Total!=0 {t.Fatalf("invalid evidence counted: %+v",got)}
  })
 }
}
func TestAuditPreservesValidMilterAndOtherConnector(t *testing.T) {
 data := "{\"connector\":\"milter\",\"action\":\"accept\",\"score\":0,\"findings\":[]}\n"+
  "{\"connector\":\"smtp\",\"action\":\"reject\"}\n"
 got,err:=analyze(strings.NewReader(data))
 if err!=nil {t.Fatal(err)}
 if got.Total!=1 || got.Malformed!=0 || got.ZeroScoreAccepted!=1 {t.Fatalf("unexpected report: %+v",got)}
}

func TestAuditRejectsNestedDuplicateEvidence(t *testing.T) {
 cases := []string{
  `{"connector":"milter","action":"accept","findings":[{"rule":"safe","rule":"unsafe"}]}`,
  `{"connector":"milter","findings":[{"rule":"safe","\u0072ule":"unsafe"}]}`,
  `{"connector":"milter","metadata":{"mta":{"status":"held","status":"released"}}}`,
  `{"connector":"smtp","metadata":{"x":1,"x":2}}`,
 }
 for _, input := range cases {
  t.Run(input, func(t *testing.T) {
   got, err := analyze(strings.NewReader(input+"\n"))
   if err != nil { t.Fatal(err) }
   if got.Malformed != 1 || got.Total != 0 { t.Fatalf("nested ambiguous evidence counted: %+v", got) }
  })
 }
}

func TestAuditAcceptsDistinctNestedEvidence(t *testing.T) {
 input := `{"connector":"milter","action":"quarantine","findings":[{"rule":"a","detail":{"score":3}},{"rule":"b","detail":{"score":4}}]}`+"\n"
 got, err := analyze(strings.NewReader(input))
 if err != nil { t.Fatal(err) }
 if got.Malformed != 0 || got.Total != 1 || got.WithFindings != 1 || got.UnconfirmedQuarantine != 1 {
  t.Fatalf("valid nested evidence rejected: %+v", got)
 }
}

func TestAuditRejectsCaseAmbiguousEventFields(t *testing.T) {
 cases := []string{
  `{"connector":"milter","action":"accept","ACTION":"reject"}`,
  `{"connector":"milter","Connector":"smtp","action":"accept"}`,
  `{"connector":"milter","action":"accept","\u0041ction":"reject"}`,
 }
 for _, input := range cases {
  got, err := analyze(strings.NewReader(input+"\n"))
  if err != nil { t.Fatal(err) }
  if got.Malformed != 1 || got.Total != 0 { t.Fatalf("ambiguous fields counted: %+v",got) }
 }
}

func TestAuditRejectsInvalidUTF8Evidence(t *testing.T) {
 input := append([]byte(`{"connector":"milter","action":"accept","note":"`), 0xff)
 input = append(input, []byte(`"}`+"\n")...)
 got, err := analyze(strings.NewReader(string(input)))
 if err != nil { t.Fatal(err) }
 if got.Malformed != 1 || got.Total != 0 { t.Fatalf("invalid UTF-8 counted: %+v",got) }
}

func TestAuditRejectsNestedCaseAliases(t *testing.T) {
 cases := []string{
  `{"connector":"milter","findings":[{"rule":"a","RULE":"b"}]}`,
  `{"connector":"milter","metadata":{"Status":"held","status":"released"}}`,
 }
 for _, input := range cases {
  got, err := analyze(strings.NewReader(input+"\n"))
  if err != nil { t.Fatal(err) }
  if got.Malformed != 1 || got.Total != 0 { t.Fatalf("nested case aliases counted: %+v", got) }
 }
}

func TestAuditRejectsUnicodeSimpleFoldAliases(t *testing.T) {
 cases := []string{
  `{"connector":"milter","action":"accept","ACTION":"reject"}`,
  `{"connector":"milter","metadata":{"K":"safe","K":"unsafe"}}`,
  `{"connector":"milter","metadata":{"K":"safe","\u212a":"unsafe"}}`,
  `{"connector":"milter","metadata":{"S":"safe","ſ":"unsafe"}}`,
 }
 for _, input := range cases {
  got, err := analyze(strings.NewReader(input+"\n"))
  if err != nil { t.Fatal(err) }
  if got.Malformed != 1 || got.Total != 0 { t.Fatalf("Unicode case alias accepted: %+v", got) }
 }
}

func TestAuditAcceptsDistinctUnicodeKeys(t *testing.T) {
 input := `{"connector":"milter","action":"accept","metadata":{"K":"safe","L":"different"}}`+"\n"
 got, err := analyze(strings.NewReader(input))
 if err != nil { t.Fatal(err) }
 if got.Malformed != 0 || got.Total != 1 { t.Fatalf("distinct keys rejected: %+v", got) }
}

func TestAuditFoldKeyMatchesEqualFold(t *testing.T) {
 pairs := [][2]string{
  {"action", "ACTION"},
  {"K", "K"},
  {"S", "ſ"},
  {"Σ", "ς"},
  {"İ", "i"},
  {"I", "ı"},
  {"Å", "Å"},
  {"a", "b"},
 }
 for _, pair := range pairs {
  got := auditFoldKey(pair[0]) == auditFoldKey(pair[1])
  want := strings.EqualFold(pair[0], pair[1])
  if got != want { t.Errorf("fold mismatch for %q and %q: got %t want %t", pair[0], pair[1], got, want) }
 }
}

func TestAuditRejectsLargeObjectCaseAlias(t *testing.T) {
 var b strings.Builder
 b.WriteString(`{"connector":"milter","action":"accept","metadata":{`)
 for i:=0;i<2000;i++ {
  if i>0 { b.WriteByte(',') }
  b.WriteString(fmt.Sprintf("%q:%d", fmt.Sprintf("field_%04d",i),i))
 }
 b.WriteString(`,"K":1,"K":2}}`)
 got,err:=analyze(strings.NewReader(b.String()+"\n"))
 if err!=nil { t.Fatal(err) }
 if got.Malformed!=1 || got.Total!=0 { t.Fatalf("large ambiguous object counted: %+v",got) }
}

func TestAuditAcceptsLargeDistinctObject(t *testing.T) {
 var b strings.Builder
 b.WriteString(`{"connector":"milter","action":"accept","metadata":{`)
 for i := 0; i < 2000; i++ {
  if i > 0 { b.WriteByte(',') }
  b.WriteString(fmt.Sprintf("%q:%d", fmt.Sprintf("field_%04d", i), i))
 }
 b.WriteString(`}}`)
 got, err := analyze(strings.NewReader(b.String()+"\n"))
 if err != nil { t.Fatal(err) }
 if got.Malformed != 0 || got.Total != 1 || got.Actions["accept"] != 1 {
  t.Fatalf("large distinct object rejected: %+v", got)
 }
}

func TestAuditOversizedRecordDoesNotHideLaterEvidence(t *testing.T) {
 oversized := `{"connector":"milter","action":"accept","padding":"` + strings.Repeat("x", 2<<20) + `"}`
 valid := `{"connector":"milter","action":"quarantine","score":0,"findings":[{"rule":"test"}]}`
 got, err := analyze(strings.NewReader(oversized+"\n"+valid+"\n"))
 if err != nil { t.Fatal(err) }
 if got.Malformed != 1 || got.Total != 1 || got.Actions["quarantine"] != 1 || got.UnconfirmedQuarantine != 1 || got.WithFindings != 1 {
  t.Fatalf("lost later valid evidence: %+v",got)
 }
}

func TestAuditOversizedUnterminatedFinalRecord(t *testing.T) {
 input := `{"connector":"milter","padding":"`+strings.Repeat("x",2<<20)
 got,err:=analyze(strings.NewReader(input))
 if err!=nil {t.Fatal(err)}
 if got.Malformed!=1 || got.Total!=0 {t.Fatalf("unexpected final oversized record result: %+v",got)}
}

func TestAuditBoundaryAndEmptyLines(t *testing.T) {
 input := "\n  \n"+`{"connector":"milter","action":"accept"}`+"\n"
 got,err:=analyze(strings.NewReader(input))
 if err!=nil {t.Fatal(err)}
 if got.Malformed!=0 || got.Total!=1 || got.Actions["accept"]!=1 {t.Fatalf("valid evidence rejected: %+v",got)}
}

func TestAuditMilterConnectorCaseAndWhitespace(t *testing.T) {
 cases := []string{"milter", "MILTER", " Milter ", "\tmIlTeR\t"}
 for _, connector := range cases {
  t.Run(fmt.Sprintf("%q",connector),func(t *testing.T) {
   line := fmt.Sprintf(`{"connector":%q,"action":"accept","score":0,"findings":[]}`,connector)
   got,err:=analyze(strings.NewReader(line+"\n"))
   if err!=nil {t.Fatal(err)}
   if got.Malformed!=0 || got.Total!=1 || got.Actions["accept"]!=1 || got.ZeroScoreAccepted!=1 {
    t.Fatalf("validator accepted connector but audit failed to count it: %+v",got)
   }
  })
 }
}

func TestAuditDoesNotCountOtherConnector(t *testing.T) {
 input := `{"connector":"smtp","action":"accept","score":0}`+"\n"
 got,err:=analyze(strings.NewReader(input))
 if err!=nil {t.Fatal(err)}
 if got.Malformed!=0 || got.Total!=0 || got.ZeroScoreAccepted!=0 {t.Fatalf("non-Milter event counted: %+v",got)}
}
