package transport

import (
 "encoding/json"
 "strings"
 "testing"
)

func TestDurableSpoolAttemptCountCanonicalAndBounded(t *testing.T) {
 base := map[string]any{
  "id": strings.Repeat("a",32),
  "sender": "",
  "recipients": []string{"user@example.org"},
  "raw": "YQ==",
  "state": "queued",
  "size": 1,
  "attempts": 0,
  "created": "2026-11-05T18:00:00Z",
  "updated": "2026-11-05T18:00:00Z",
  "next_attempt": "2026-11-05T18:00:00Z",
 }
 encoded,err:=json.Marshal(base)
 if err!=nil {t.Fatal(err)}
 for _,tc:=range []struct{value string; valid bool}{
  {"0",true},{"1",true},{"1000000",true},
  {"1000001",false},{"4294967296",false},
  {`"1"`,false},{"-0",false},{"-1",false},
  {"01",false},{"1.0",false},{"1e0",false},
  {"1E+0",false},{"null",false},{"true",false},
  {"9223372036854775808",false},
 } {
  t.Run(tc.value,func(t *testing.T){
   changed:=strings.Replace(string(encoded),`"attempts":0`,`"attempts":`+tc.value,1)
   if changed==string(encoded) {t.Fatal("attempts fixture missing")}
   err:=validateCanonicalSpoolRecordJSON([]byte(changed))
   if tc.valid && err!=nil {t.Fatalf("valid count rejected: %v",err)}
   if !tc.valid && err==nil {t.Fatalf("invalid count %s accepted",tc.value)}
  })
 }
}
