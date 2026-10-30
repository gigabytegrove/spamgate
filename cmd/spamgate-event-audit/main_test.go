package main

import (
 "strings"
 "testing"
)
func TestAnalyzeMilterEvents(t *testing.T) {
 data:=strings.Join([]string{
  `{"connector":"milter","action":"accept","score":0}`,
  `{"connector":"milter","action":"quarantine","score":9,"mta_action_state":"pending"}`,
  `{"connector":"milter","action":"quarantine","score":10,"mta_action_state":"held"}`,
  `{"connector":"smtp","action":"reject","score":2}`,
  `not-json`,
 },"\n")
 got,err:=analyze(strings.NewReader(data))
 if err!=nil {t.Fatal(err)}
 if got.Total!=3 || got.Malformed!=1 || got.Actions["quarantine"]!=2 || got.ZeroScore!=1 || got.UnconfirmedQuarantine!=1 {
  t.Fatalf("unexpected audit result: %+v",got)
 }
}
func TestAnalyzeOversizedEventFails(t *testing.T) {
 _,err:=analyze(strings.NewReader(strings.Repeat("x",2<<20+10)))
 if err==nil {t.Fatal("expected bounded scanner failure")}
}
func TestAnalyzeEmpty(t *testing.T) {
 got,err:=analyze(strings.NewReader("\n"))
 if err!=nil || got.Total!=0 {t.Fatalf("unexpected result %+v %v",got,err)}
}
