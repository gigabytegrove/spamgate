package main

import (
 "strings"
 "testing"
)

func TestCorpusEvidenceSchema(t *testing.T) {
 valid := `{"id":"clean-1","truth":"clean","score":0}`+"\n"+`{"id":"spam-1","truth":"spam","score":1}`+"\n"
 if _, err := evaluate(strings.NewReader(valid), 0.5); err != nil { t.Fatalf("valid corpus: %v", err) }
 cases := map[string]string{
  "missing-score": `{"id":"clean-1","truth":"clean"}`,
  "missing-truth": `{"id":"clean-1","score":0}`,
  "missing-id": `{"truth":"clean","score":0}`,
  "null-score": `{"id":"clean-1","truth":"clean","score":null}`,
  "null-id": `{"id":null,"truth":"clean","score":0}`,
  "duplicate-score": `{"id":"clean-1","truth":"clean","score":0,"score":1}`,
  "duplicate-truth": `{"id":"clean-1","truth":"clean","truth":"spam","score":0}`,
  "unknown-field": `{"id":"clean-1","truth":"clean","score":0,"verified":true}`,
  "array": `[{"id":"clean-1","truth":"clean","score":0}]`,
  "wrong-type": `{"id":"clean-1","truth":"clean","score":"0"}`,
  "trailing-value": `{"id":"clean-1","truth":"clean","score":0}{}`,
 }
 for name, raw := range cases {
  t.Run(name, func(t *testing.T) {
   if _, err := evaluate(strings.NewReader(raw+"\n"+valid), 0.5); err == nil {
    t.Fatalf("accepted ambiguous corpus sample: %s", raw)
   }
  })
 }
}

func TestCorpusEvidenceSchemaValidZeroAndReorderedFields(t *testing.T) {
 raw := `{"score":0,"truth":"clean","id":"a"}`+"\n"+`{"score":1,"id":"b","truth":"spam"}`+"\n"
 result, err := evaluate(strings.NewReader(raw), 0.5)
 if err != nil || result.TN != 1 || result.TP != 1 { t.Fatalf("result=%+v err=%v",result,err) }
}
