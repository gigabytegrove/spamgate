package transport

import (
 "encoding/json"
 "strings"
 "testing"
 "time"
)
func TestDurableLifecycleRejectsAmbiguousState(t *testing.T) {
 now:=time.Now().UTC().Format(time.RFC3339Nano)
 base:=map[string]any{"id":strings.Repeat("a",32),"sender":"","recipients":[]string{"user@example.org"},"raw":"YQ==","state":"queued","size":1,"attempts":0,"created":now,"updated":now,"next_attempt":now}
 check:=func(m map[string]any) error {b,e:=json.Marshal(m);if e!=nil {t.Fatal(e)};return validateCanonicalSpoolRecordJSON(b)}
 if err:=check(base);err!=nil {t.Fatalf("valid durable record: %v",err)}
 cases:=[]struct{name,key string;value any;remove bool}{
 {"missing attempts","attempts",nil,true},{"null attempts","attempts",nil,false},{"fractional attempts","attempts",1.5,false},
 {"negative attempts","attempts",-1,false},{"overflow attempts","attempts",4294967296,false},
 {"excessive attempts","attempts",MaxDeliveryAttempts+1,false},{"string attempts","attempts","1",false},
 {"missing created","created",nil,true},{"null updated","updated",nil,false},
 {"invalid next attempt","next_attempt","not-a-date",false},{"numeric created","created",123,false},
 {"null delivered at","delivered_at",nil,false},{"invalid delivered at","delivered_at","yesterday",false},
 }
 for _,tc:=range cases {t.Run(tc.name,func(t *testing.T){
  m:=make(map[string]any,len(base)+1);for k,v:=range base {m[k]=v}
  if tc.remove {delete(m,tc.key)} else {m[tc.key]=tc.value}
  if err:=check(m);err==nil {t.Fatal("malformed persisted delivery state accepted")}
 })}
}
