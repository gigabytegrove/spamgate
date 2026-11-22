package spooltrend

import (
 "strings"
 "testing"
 "time"
)

func TestFreshnessPolicy(t *testing.T) {
 now := time.Date(2026,11,21,20,0,0,0,time.UTC)
 base := Snapshot{CapturedAt:now.Add(-10*time.Minute)}
 later := Snapshot{CapturedAt:now.Add(-time.Minute)}
 cases := []struct{name string; a,b Snapshot; p FreshnessPolicy; want string}{
  {"valid",base,later,FreshnessPolicy{true,2*time.Minute,15*time.Minute},""},
  {"stale",base,later,FreshnessPolicy{true,30*time.Second,0},"age"},
  {"gap",base,later,FreshnessPolicy{true,0,5*time.Minute},"gap"},
  {"reversed",later,base,FreshnessPolicy{},"follow"},
  {"future",base,Snapshot{CapturedAt:now.Add(6*time.Minute)},FreshnessPolicy{},"future"},
  {"legacy-denied",Snapshot{},Snapshot{},FreshnessPolicy{RequireTimestamps:true},"required"},
  {"legacy-allowed",Snapshot{},Snapshot{},FreshnessPolicy{},""},
  {"legacy-with-age",Snapshot{},Snapshot{},FreshnessPolicy{MaxSnapshotAge:time.Minute},"required"},
  {"negative-age",base,later,FreshnessPolicy{MaxSnapshotAge:-1},"nonnegative"},
  {"negative-gap",base,later,FreshnessPolicy{MaxSnapshotGap:-1},"nonnegative"},
  {"boundary",base,later,FreshnessPolicy{true,time.Minute,9*time.Minute},""},
 }
 for _,tc:=range cases {
  t.Run(tc.name,func(t *testing.T){
   err:=CheckFreshness(tc.a,tc.b,tc.p,now)
   if tc.want=="" && err!=nil {t.Fatal(err)}
   if tc.want!="" && (err==nil || !strings.Contains(err.Error(),tc.want)){t.Fatalf("expected %q, got %v",tc.want,err)}
  })
 }
}
