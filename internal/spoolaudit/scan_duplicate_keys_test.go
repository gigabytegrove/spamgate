package spoolaudit

import (
 "encoding/json"
 "strings"
 "testing"
)

func TestScanEnvelopeDuplicateKeys(t *testing.T) {
 const id="0123456789abcdef0123456789abcdef"
 rec:=record{ID:id,Sender:"",Recipients:[]string{"a@example.test"}}
 cases:=[]struct{name,scan string; reject bool}{
  {"valid identity",`{"id":"`+id+`","sender":"","recipients":["a@example.test"],"score":3}`,false},
  {"duplicate ID same value",`{"id":"`+id+`","id":"`+id+`","sender":"","recipients":["a@example.test"]}`,true},
  {"duplicate ID conflicting value",`{"id":"wrong","id":"`+id+`","sender":"","recipients":["a@example.test"]}`,true},
  {"duplicate sender",`{"id":"`+id+`","sender":"attacker@example.test","sender":"","recipients":["a@example.test"]}`,true},
  {"duplicate recipients",`{"id":"`+id+`","sender":"","recipients":["b@example.test"],"recipients":["a@example.test"]}`,true},
  {"duplicate unrelated field",`{"id":"`+id+`","sender":"","recipients":["a@example.test"],"score":1,"score":9}`,true},
  {"escaped duplicate key",`{"id":"`+id+`","\u0069d":"`+id+`","sender":"","recipients":["a@example.test"]}`,true},
  {"nested duplicate not envelope identity",`{"id":"`+id+`","sender":"","recipients":["a@example.test"],"metadata":{"x":1,"x":2}}`,true},
  {"duplicate nested array object",`{"id":"`+id+`","sender":"","recipients":["a@example.test"],"events":[{"code":"pass","code":"fail"}]}`,true},
  {"escaped duplicate nested key",`{"id":"`+id+`","sender":"","recipients":["a@example.test"],"events":[{"code":"pass","\u0063ode":"fail"}]}`,true},
  {"valid nested evidence",`{"id":"`+id+`","sender":"","recipients":["a@example.test"],"events":[{"code":"pass"},{"code":"fail"}]}`,false},
  {"trailing JSON",`{"id":"`+id+`","sender":"","recipients":["a@example.test"]} true`,true},
  {"malformed value",`{"id":"`+id+`","sender":"","recipients":["a@example.test"],"score":}`,true},
  {"legacy null",`null`,false},
 }
 for _,tc:=range cases {
  t.Run(tc.name,func(t *testing.T){
   item:=rec
   item.Scan=json.RawMessage(tc.scan)
   err:=validateAuditScanEnvelope(item)
   if tc.reject && (err==nil || !strings.Contains(err.Error(),"scan envelope")) {t.Fatalf("expected scan envelope rejection, got %v",err)}
   if !tc.reject && err!=nil {t.Fatalf("unexpected rejection: %v",err)}
  })
 }
}
