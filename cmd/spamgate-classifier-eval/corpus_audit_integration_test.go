package main

import (
 "bytes"
 "encoding/json"
 "testing"
)
func TestRunCorpusAuditFlag(t *testing.T) {
 var out bytes.Buffer
 corpus:=`[{"id":"1","tenant":"alpha","spam":true,"score":9},{"id":"2","tenant":"alpha","spam":false,"score":1}]`
 if err:=run([]string{"-audit-corpus"},bytes.NewBufferString(corpus),&out);err!=nil {t.Fatal(err)}
 var result struct {
  Evaluation json.RawMessage `json:"evaluation"`
  CorpusAudit struct {
   Total int `json:"total"`
   Spam int `json:"spam"`
   Clean int `json:"clean"`
  } `json:"corpus_audit"`
 }
 if err:=json.Unmarshal(out.Bytes(),&result);err!=nil {t.Fatal(err)}
 if len(result.Evaluation)==0||result.CorpusAudit.Total!=2||result.CorpusAudit.Spam!=1||result.CorpusAudit.Clean!=1 {t.Fatalf("wrong output: %s",out.String())}
}
