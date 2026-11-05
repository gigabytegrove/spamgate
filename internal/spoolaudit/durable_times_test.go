package spoolaudit

import (
 "strings"
 "testing"
)

func TestValidateDurableTimes(t *testing.T) {
 base:=`{"created":"2026-11-05T12:00:00Z","updated":"2026-11-05T12:00:01.123456789Z","next_attempt":"2026-11-05T12:05:00-05:00"}`
 cases:=[]struct{name,body string;valid bool}{
  {"valid",base,true},
  {"valid delivered at",strings.Replace(base,"}",`,"delivered_at":"2026-11-05T12:10:00Z"}`,1),true},
  {"missing created",`{"updated":"2026-11-05T12:00:00Z","next_attempt":"2026-11-05T12:00:00Z"}`,false},
  {"missing updated",`{"created":"2026-11-05T12:00:00Z","next_attempt":"2026-11-05T12:00:00Z"}`,false},
  {"missing next",`{"created":"2026-11-05T12:00:00Z","updated":"2026-11-05T12:00:00Z"}`,false},
  {"null created",strings.Replace(base,`"created":"2026-11-05T12:00:00Z"`,`"created":null`,1),false},
  {"null updated",strings.Replace(base,`"updated":"2026-11-05T12:00:01.123456789Z"`,`"updated":null`,1),false},
  {"null next",strings.Replace(base,`"next_attempt":"2026-11-05T12:05:00-05:00"`,`"next_attempt":null`,1),false},
  {"numeric created",strings.Replace(base,`"created":"2026-11-05T12:00:00Z"`,`"created":42`,1),false},
  {"boolean updated",strings.Replace(base,`"updated":"2026-11-05T12:00:01.123456789Z"`,`"updated":true`,1),false},
  {"invalid next",strings.Replace(base,"2026-11-05T12:05:00-05:00","yesterday",1),false},
  {"missing timezone",strings.Replace(base,"2026-11-05T12:00:00Z","2026-11-05T12:00:00",1),false},
  {"null delivered at",strings.Replace(base,"}",`,"delivered_at":null}`,1),false},
  {"number delivered at",strings.Replace(base,"}",`,"delivered_at":123}`,1),false},
  {"invalid delivered at",strings.Replace(base,"}",`,"delivered_at":"not-a-time"}`,1),false},
  {"empty delivered at",strings.Replace(base,"}",`,"delivered_at":""}`,1),false},
  {"invalid top level",`[]`,false},
 }
 for _,tc:=range cases {
  t.Run(tc.name,func(t *testing.T){
   err:=validateDurableTimes([]byte(tc.body))
   if (err==nil)!=tc.valid {t.Fatalf("valid=%t err=%v",tc.valid,err)}
  })
 }
}
