package transport

import (
 "encoding/json"
 "strings"
 "testing"
)

func TestCanonicalSpoolRecordJSON(t *testing.T) {
 base := map[string]any{
  "id": strings.Repeat("a", 32), "sender": "", "recipients": []string{"user@example.org"},
  "raw": "SGVsbG8=", "state": "queued", "size": 5,
 }
 encode := func(m map[string]any) []byte {
  t.Helper()
  b, err := json.Marshal(m)
  if err != nil { t.Fatal(err) }
  return b
 }
 if err := validateCanonicalSpoolRecordJSON(encode(base)); err != nil {
  t.Fatalf("valid bounce envelope refused: %v", err)
 }
 for _, tc := range []struct{
  name string
  change func(map[string]any)
 }{
  {"uppercase sender alias", func(m map[string]any){m["Sender"]="attacker@example.org"}},
  {"uppercase recipient alias", func(m map[string]any){m["Recipients"]=[]string{"attacker@example.org"}}},
  {"uppercase state alias", func(m map[string]any){m["State"]="delivered"}},
  {"missing sender", func(m map[string]any){delete(m,"sender")}},
  {"null sender", func(m map[string]any){m["sender"]=nil}},
  {"null recipients", func(m map[string]any){m["recipients"]=nil}},
  {"null recipient element", func(m map[string]any){m["recipients"]=[]any{nil}}},
  {"number recipient element", func(m map[string]any){m["recipients"]=[]any{42}}},
  {"empty recipient element", func(m map[string]any){m["recipients"]=[]string{""}}},
  {"object recipient element", func(m map[string]any){m["recipients"]=[]any{map[string]any{"address":"x"}}}},
  {"missing raw", func(m map[string]any){delete(m,"raw")}},
  {"null raw", func(m map[string]any){m["raw"]=nil}},
  {"null state", func(m map[string]any){m["state"]=nil}},
  {"fractional size", func(m map[string]any){m["size"]=2.5}},
  {"null size", func(m map[string]any){m["size"]=nil}},
 } {
  t.Run(tc.name,func(t *testing.T){
   m:=make(map[string]any,len(base)+1)
   for k,v:=range base {m[k]=v}
   tc.change(m)
   if err:=validateCanonicalSpoolRecordJSON(encode(m));err==nil {t.Fatal("malformed durable envelope accepted")}
  })
 }
 for _, raw := range []string{
  `{"id":"a","sender":"","recipients":["x"],"raw":"YQ==","state":"queued","size":1,"S\u0065nder":"spoof"}`,
  `[]`, `null`, `{}`,
 } {
  t.Run(raw,func(t *testing.T){
   if err:=validateCanonicalSpoolRecordJSON([]byte(raw));err==nil {t.Fatal("ambiguous or incomplete JSON accepted")}
  })
 }
 m:=make(map[string]any,len(base)+1)
 for k,v:=range base {m[k]=v}
 m["future_extension"]=map[string]any{"anything":true}
 if err:=validateCanonicalSpoolRecordJSON(encode(m));err!=nil {t.Fatalf("extension rejected: %v",err)}
}
