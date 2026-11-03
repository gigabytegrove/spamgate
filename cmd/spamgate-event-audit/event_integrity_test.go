package main

import (
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
