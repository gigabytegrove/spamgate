package spooltrend

import (
 "strings"
 "testing"
)

func TestPolicyIndependentLimits(t *testing.T) {
 before:=snapshot(map[string]int{"queued":1,"delivering":1,"dead":1})
 after:=snapshot(map[string]int{"queued":2,"delivering":3,"dead":2})
 before.Examined++;before.Pending=1
 after.Examined+=3;after.Pending=3
 p:=Policy{MaxQueuedGrowth:1,MaxDeadGrowth:1,MaxDeliveringGrowth:1,MaxPendingGrowth:1,MaxDeadCount:1}
 r,err:=CompareWithPolicy(before,after,p)
 if err!=nil{t.Fatal(err)}
 if r.GatePassed || len(r.GateFailures)!=3 {t.Fatalf("expected three independent failures: %+v",r)}
 for _,fragment:=range []string{"delivering_growth=2","pending_growth=2","dead_count=2"} {
  if !strings.Contains(strings.Join(r.GateFailures,";"),fragment){t.Fatalf("missing %s: %+v",fragment,r)}
 }
 p.MaxDeliveringGrowth=2;p.MaxPendingGrowth=2;p.MaxDeadCount=2
 r,err=CompareWithPolicy(before,after,p)
 if err!=nil||!r.GatePassed{t.Fatalf("inclusive limits: %+v %v",r,err)}
}
func TestPolicyRejectsInvalidLimitAndUnqualifiedInput(t *testing.T) {
 a:=snapshot(map[string]int{"queued":1})
 p:=Policy{MaxQueuedGrowth:-1,MaxDeadGrowth:-1,MaxDeliveringGrowth:-1,MaxPendingGrowth:-1,MaxDeadCount:-2}
 if _,err:=CompareWithPolicy(a,a,p);err==nil{t.Fatal("accepted invalid limit")}
 p.MaxDeadCount=-1
 *a.GatePassed=false
 if _,err:=CompareWithPolicy(a,a,p);err==nil{t.Fatal("accepted unqualified input")}
}
func TestPolicyDisabledLimits(t *testing.T) {
 a:=snapshot(map[string]int{"dead":1})
 b:=snapshot(map[string]int{"dead":100})
 p:=Policy{-1,-1,-1,-1,-1}
 r,err:=CompareWithPolicy(a,b,p)
 if err!=nil||!r.GatePassed{t.Fatalf("disabled limits: %+v %v",r,err)}
}
