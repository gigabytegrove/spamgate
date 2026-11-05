package spoolaudit

import (
 "encoding/json"
 "strings"
 "testing"
)

func TestScanEnvelopeRejectsNoncanonicalIdentityKeys(t *testing.T) {
 const id="0123456789abcdef0123456789abcdef"
 base:=record{ID:id,Sender:"",Recipients:[]string{"a@example.test"}}
 cases:=[]struct{name,scan string; bad bool}{
  {"canonical empty reverse path",`{"id":"`+id+`","sender":"","recipients":["a@example.test"],"score":3}`,false},
  {"uppercase ID only",`{"ID":"`+id+`","sender":"","recipients":["a@example.test"]}`,true},
  {"mixed-case sender only",`{"id":"`+id+`","Sender":"","recipients":["a@example.test"]}`,true},
  {"uppercase recipients only",`{"id":"`+id+`","sender":"","Recipients":["a@example.test"]}`,true},
  {"canonical plus alternate ID",`{"id":"`+id+`","ID":"`+id+`","sender":"","recipients":["a@example.test"]}`,true},
  {"canonical plus conflicting sender",`{"id":"`+id+`","sender":"","SENDER":"other@example.test","recipients":["a@example.test"]}`,true},
  {"canonical plus conflicting recipients",`{"id":"`+id+`","sender":"","recipients":["a@example.test"],"RECIPIENTS":["b@example.test"]}`,true},
  {"wrong typed ID",`{"id":123,"sender":"","recipients":["a@example.test"]}`,true},
  {"wrong typed sender",`{"id":"`+id+`","sender":false,"recipients":["a@example.test"]}`,true},
  {"wrong typed recipients",`{"id":"`+id+`","sender":"","recipients":"a@example.test"}`,true},
  {"null sender",`{"id":"`+id+`","sender":null,"recipients":["a@example.test"]}`,true},
  {"legacy null","null",false},
 }
 for _,tc:=range cases {
  t.Run(tc.name,func(t *testing.T){
   rec:=base
   rec.Scan=json.RawMessage(tc.scan)
   err:=validateAuditScanEnvelope(rec)
   if tc.bad && (err==nil || !strings.Contains(err.Error(),"scan envelope")) {
    t.Fatalf("expected scan envelope error, got %v",err)
   }
   if !tc.bad && err!=nil {t.Fatalf("valid envelope rejected: %v",err)}
  })
 }
}
