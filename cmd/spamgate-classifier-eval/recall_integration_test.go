package main

import (
 "bytes"
 "encoding/json"
 "strings"
 "testing"
)
func TestRecallOnlyGateFailsAndEmitsEvidence(t *testing.T){
 input:=`[{"id":"a","tenant":"alpha","spam":true,"score":0},{"id":"b","tenant":"beta","spam":true,"score":10}]`
 var out bytes.Buffer
 err:=run([]string{"-threshold=5","-min-recall=0.5","-min-spam=1"},strings.NewReader(input),&out)
 if err==nil {t.Fatal("expected tenant recall gate failure")}
 var report struct {RecallGates struct {Passed bool `json:"passed"`; Tenants []struct {Tenant string `json:"tenant"`;Passed bool `json:"passed"`} `json:"tenants"`} `json:"recall_gates"`}
 if e:=json.Unmarshal(out.Bytes(),&report);e!=nil {t.Fatal(e)}
 if report.RecallGates.Passed||len(report.RecallGates.Tenants)!=2||report.RecallGates.Tenants[0].Passed {t.Fatalf("unexpected recall result: %s",out.String())}
}
func TestCombinedGatesProduceBothReports(t *testing.T){
 input:=`[{"id":"a","tenant":"alpha","spam":true,"score":10},{"id":"b","tenant":"alpha","spam":false,"score":0}]`
 var out bytes.Buffer
 _=run([]string{"-min-recall=0.1","-min-spam=1","-max-fp-upper=0.9","-min-clean=1"},strings.NewReader(input),&out)
 var result map[string]json.RawMessage
 if err:=json.Unmarshal(out.Bytes(),&result);err!=nil {t.Fatal(err)}
 if len(result["gates"])==0||len(result["recall_gates"])==0 {t.Fatalf("missing gate evidence: %s",out.String())}
}
