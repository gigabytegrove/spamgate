package spooltrend

import (
 "testing"
 "time"
)

func TestTimestampedSnapshotsRequireStrictOrder(t *testing.T) {
 now:=time.Now().UTC().Add(-time.Minute)
 for _,tc:=range []struct{name string;before,after time.Time;wantError bool}{
  {"ordered",now,now.Add(time.Second),false},
  {"same",now,now,true},
  {"reversed",now.Add(time.Second),now,true},
  {"mixed-legacy",time.Time{},now,true},
  {"mixed-new",now,time.Time{},true},
  {"legacy",time.Time{},time.Time{},false},
  {"future",now,time.Now().Add(10*time.Minute),true},
  {"ancient",time.Date(1990,1,1,0,0,0,0,time.UTC),now,true},
 } {
  t.Run(tc.name,func(t *testing.T){
   a:=snapshot(map[string]int{"queued":1})
   b:=snapshot(map[string]int{"queued":2})
   a.CapturedAt=tc.before
   b.CapturedAt=tc.after
   _,err:=Compare(a,b,-1,-1)
   if (err!=nil)!=tc.wantError {t.Fatalf("expected error %v, got %v",tc.wantError,err)}
  })
 }
}
