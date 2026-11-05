package spoolaudit

import (
 "encoding/json"
 "strings"
 "testing"
)

// Go's encoding/json unmarshals null into a string as its zero value.
// An envelope audit must not confuse that malformed value with an
// explicitly serialized recipient address.
func TestScanEnvelopeRecipientElementTypes(t *testing.T) {
 const id="0123456789abcdef0123456789abcdef"
 cases:=[]struct{
  name string
  recipients string
  original []string
  reject bool
 }{
  {"valid single",`["a@example.test"]`,[]string{"a@example.test"},false},
  {"valid ordered multiple",`["a@example.test","b@example.test"]`,[]string{"a@example.test","b@example.test"},false},
  {"null element with empty original",`[null]`,[]string{""},true},
  {"null element in multiple",`["a@example.test",null]`,[]string{"a@example.test",""},true},
  {"numeric element",`[12]`,[]string{"12"},true},
  {"boolean element",`[false]`,[]string{"false"},true},
  {"object element",`[{}]`,[]string{""},true},
  {"null array",`null`,nil,true},
  {"string instead of array",`"a@example.test"`,[]string{"a@example.test"},true},
  {"empty array matching nil original",`[]`,nil,false},
  {"escaped equivalent string",`["a\\u0040example.test"]`,[]string{"a@example.test"},false},
  {"recipient order changed",`["b@example.test","a@example.test"]`,[]string{"a@example.test","b@example.test"},true},
 }
 for _,tc:=range cases {
  t.Run(tc.name,func(t *testing.T){
   rec:=record{ID:id,Sender:"",Recipients:tc.original,
    Scan:json.RawMessage(`{"id":"`+id+`","sender":"","recipients":`+tc.recipients+`}`)}
   err:=validateAuditScanEnvelope(rec)
   if tc.reject && (err==nil || !strings.Contains(err.Error(),"scan envelope")) {
    t.Fatalf("expected malformed scan envelope rejection, got %v",err)
   }
   if !tc.reject && err!=nil {t.Fatalf("unexpected rejection: %v",err)}
  })
 }
}
