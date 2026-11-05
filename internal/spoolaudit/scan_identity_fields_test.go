package spoolaudit

import (
 "encoding/json"
 "strings"
 "testing"
)

func TestAuditScanEnvelopeExplicitIdentityFields(t *testing.T) {
 const id = "0123456789abcdef0123456789abcdef"
 for _, tc := range []struct {
  name, sender, scan string
  recipients []string
  wantError bool
 }{
  {"empty reverse path explicitly bound", "", `{"id":"`+id+`","sender":"","recipients":["a@example.test"]}`, []string{"a@example.test"}, false},
  {"missing sender on empty reverse path", "", `{"id":"`+id+`","recipients":["a@example.test"]}`, []string{"a@example.test"}, true},
  {"null sender on empty reverse path", "", `{"id":"`+id+`","sender":null,"recipients":["a@example.test"]}`, []string{"a@example.test"}, true},
  {"missing id", "sender@example.test", `{"sender":"sender@example.test","recipients":["a@example.test"]}`, []string{"a@example.test"}, true},
  {"null id", "sender@example.test", `{"id":null,"sender":"sender@example.test","recipients":["a@example.test"]}`, []string{"a@example.test"}, true},
  {"missing recipients", "sender@example.test", `{"id":"`+id+`","sender":"sender@example.test"}`, []string{"a@example.test"}, true},
  {"null recipients", "sender@example.test", `{"id":"`+id+`","sender":"sender@example.test","recipients":null}`, []string{"a@example.test"}, true},
  {"recipient order changed", "sender@example.test", `{"id":"`+id+`","sender":"sender@example.test","recipients":["b@example.test","a@example.test"]}`, []string{"a@example.test","b@example.test"}, true},
  {"multi recipient exact match", "sender@example.test", `{"id":"`+id+`","sender":"sender@example.test","recipients":["a@example.test","b@example.test"]}`, []string{"a@example.test","b@example.test"}, false},
  {"legacy null scan", "", "null", []string{"a@example.test"}, false},
  {"legacy absent scan", "", "", []string{"a@example.test"}, false},
 } {
  t.Run(tc.name,func(t *testing.T){
   rec:=record{ID:id,Sender:tc.sender,Recipients:tc.recipients,Scan:json.RawMessage(tc.scan)}
   err:=validateAuditScanEnvelope(rec)
   if tc.wantError && (err==nil || !strings.Contains(err.Error(),"scan envelope")) {
    t.Fatalf("expected explicit scan envelope rejection, got %v",err)
   }
   if !tc.wantError && err!=nil {t.Fatalf("valid scan envelope rejected: %v",err)}
  })
 }
}
