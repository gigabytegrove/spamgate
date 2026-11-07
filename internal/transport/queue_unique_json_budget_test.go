package transport

import (
 "strconv"
 "strings"
 "testing"
)

func TestDurableJSONStructuralBudgets(t *testing.T) {
 cases := []struct { name, input, errorPart string }{
  {"normal nested", `{"scan":{"symbols":[{"name":"SPF"},{"name":"DKIM"}]}}`, ""},
  {"duplicate escaped alias", `{"id":1,"\u005cu0069d":2}`, "duplicate"},
  {"maximum key length", `{"`+strings.Repeat("k",maxDurableJSONKeyBytes)+`":1}`, ""},
  {"oversized key", `{"`+strings.Repeat("k",maxDurableJSONKeyBytes+1)+`":1}`, "key too long"},
  {"key count limit", buildDurableObject(maxDurableJSONObjectKeys), ""},
  {"key count exceeded", buildDurableObject(maxDurableJSONObjectKeys+1), "key limit"},
  {"array token limit", `[`+strings.Repeat("0,", maxDurableJSONTokens)+`0]`, "token budget"},
  {"deep nesting", strings.Repeat("[",maxDurableJSONDepth+1)+`0`+strings.Repeat("]",maxDurableJSONDepth+1), "nesting"},
 }
 for _, tc := range cases { t.Run(tc.name,func(t *testing.T){
  err:=validateUniqueDurableJSON([]byte(tc.input))
  if tc.errorPart=="" && err!=nil {t.Fatalf("unexpected error: %v",err)}
  if tc.errorPart!="" && (err==nil || !strings.Contains(err.Error(),tc.errorPart)){t.Fatalf("expected %q, got %v",tc.errorPart,err)}
 }) }
}
func buildDurableObject(n int) string {
 var b strings.Builder
 b.WriteByte('{')
 for i:=0;i<n;i++ {
  if i>0 {b.WriteByte(',')}
  b.WriteString(strconv.Quote("key"+strconv.Itoa(i)))
  b.WriteString(":0")
 }
 b.WriteByte('}')
 return b.String()
}
