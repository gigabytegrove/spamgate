package transport

import (
 "encoding/json"
 "strings"
 "testing"
)

func TestStrictDurableNonnegativeInteger(t *testing.T) {
 valid := map[string]int64{"0":0, "1":1, "9223372036854775807":9223372036854775807}
 for input, want := range valid {
  got, err := strictDurableNonnegativeInteger([]byte(input))
  if err != nil || got != want { t.Errorf("%q: got %d, %v; want %d", input,got,err,want) }
 }
 invalid := []string{"", "-0", "-1", "+1", "01", "1.0", "1e0", "1E2",
  "9223372036854775808", "18446744073709551615", "null", "true",
  `"1"`, " 1", "1 ", "1\n", "1,2", "1x"}
 for _, input := range invalid {
  t.Run(input,func(t *testing.T) {
   if _,err:=strictDurableNonnegativeInteger([]byte(input));err==nil {
    t.Fatalf("noncanonical integer %q accepted",input)
   }
  })
 }
}

func TestDurableSpoolRejectsNoncanonicalSizeTypes(t *testing.T) {
 // Use a complete legacy record to verify the persisted-record entrypoint,
 // not only the integer helper.
 base := map[string]any{
  "id":strings.Repeat("a",32), "sender":"", "recipients":[]string{"user@example.org"},
  "raw":"YQ==", "state":"queued", "size":1, "attempts":0,
  "created":"2026-11-05T18:00:00Z", "updated":"2026-11-05T18:00:00Z",
  "next_attempt":"2026-11-05T18:00:00Z",
 }
 encoded,err:=json.Marshal(base)
 if err!=nil {t.Fatal(err)}
 if err:=validateCanonicalSpoolRecordJSON(encoded);err!=nil {t.Fatalf("baseline rejected: %v",err)}
 for _,size:=range []string{`"1"`,"-0","1.0","1e0","1E+0","9223372036854775808"} {
  t.Run(size,func(t *testing.T){
   mutated:=strings.Replace(string(encoded),`"size":1`,`"size":`+size,1)
   if mutated==string(encoded) {t.Fatal("fixture size field not found")}
   if err:=validateCanonicalSpoolRecordJSON([]byte(mutated));err==nil {
    t.Fatalf("noncanonical durable size %s accepted",size)
   }
  })
 }
}
