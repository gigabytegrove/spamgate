package spooltrend

import (
 "encoding/json"
 "os"
 "path/filepath"
 "strings"
 "testing"
)

func snapshot(states map[string]int) Snapshot {
 ok:=true
 total:=0
 for _,n:=range states {total+=n}
 return Snapshot{GatePassed:&ok,Examined:total,Published:total,States:states,Findings:[]json.RawMessage{}}
}
func TestGrowthGates(t *testing.T){
 a:=snapshot(map[string]int{"queued":2,"dead":0})
 b:=snapshot(map[string]int{"queued":5,"dead":2})
 r,err:=Compare(a,b,2,1)
 if err!=nil||r.GatePassed||len(r.GateFailures)!=2||r.QueueDelta!=3||r.DeadDelta!=2 {t.Fatalf("%+v %v",r,err)}
 r,err=Compare(a,b,3,2)
 if err!=nil||!r.GatePassed {t.Fatalf("%+v %v",r,err)}
}
func TestRefuseUnqualified(t *testing.T){
 a:=snapshot(map[string]int{})
 b:=snapshot(map[string]int{})
 *a.GatePassed=false
 if _,err:=Compare(a,b,-1,-1);err==nil{t.Fatal("accepted failed audit")}
}
func TestLoadRejectsUnsafeEvidence(t *testing.T){
 dir:=t.TempDir()
 path:=filepath.Join(dir,"report.json")
 good:=`{"gate_passed":true,"examined":1,"published":1,"pending":0,"states":{"queued":1},"findings":[],"truncated":false}`
 for _,tc:=range []struct{name,body string;valid bool}{
  {"valid",good,true},
  {"failed",strings.Replace(good,"true","false",1),false},
  {"trailing",good+" {}",false},
  {"missing",`{"gate_passed":true}`,false},
  {"negative",strings.Replace(good,`"queued":1`,`"queued":-1`,1),false},
  {"bad-state",strings.Replace(good,`"queued":1`,`"unknown":1`,1),false},
  {"null-gate",strings.Replace(good,`"gate_passed":true`,`"gate_passed":null`,1),false},
  {"null-count",strings.Replace(good,`"examined":1`,`"examined":null`,1),false},
  {"null-pending",strings.Replace(good,`"pending":0`,`"pending":null`,1),false},
  {"null-states",strings.Replace(good,`"states":{"queued":1}`,`"states":null`,1),false},
  {"null-findings",strings.Replace(good,`"findings":[]`,`"findings":null`,1),false},
  {"null-truncated",strings.Replace(good,`"truncated":false`,`"truncated":null`,1),false},
 }{
  t.Run(tc.name,func(t *testing.T){
   if err:=os.WriteFile(path,[]byte(tc.body),0600);err!=nil{t.Fatal(err)}
   _,err:=Load(path)
   if (err==nil)!=tc.valid{t.Fatalf("valid=%v err=%v",tc.valid,err)}
  })
 }
 if err:=os.Symlink(path,filepath.Join(dir,"link"));err!=nil{t.Fatal(err)}
 if _,err:=Load(filepath.Join(dir,"link"));err==nil{t.Fatal("accepted symlink")}
}

func TestRejectIncompletePublishedStates(t *testing.T) {
 a:=snapshot(map[string]int{"queued":1})
 b:=snapshot(map[string]int{"queued":1})
 b.Published=2
 b.Examined=2
 if _,err:=Compare(a,b,-1,-1);err==nil {t.Fatal("accepted missing verified state")}
 b=snapshot(map[string]int{"queued":1})
 b.States["unexpected"]=1
 if _,err:=Compare(a,b,-1,-1);err==nil {t.Fatal("accepted unknown state")}
 b=snapshot(map[string]int{"queued":1})
 b.States["dead"]=-1
 if _,err:=Compare(a,b,-1,-1);err==nil {t.Fatal("accepted negative state")}
 b=snapshot(map[string]int{"queued":1})
 b.Pending=1
 if _,err:=Compare(a,b,-1,-1);err==nil {t.Fatal("accepted impossible pending count")}
}
