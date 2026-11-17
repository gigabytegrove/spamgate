package qualification

import (
 "math"
 "strings"
 "testing"
)

func stabilitySamples() []Sample {
 return []Sample{
  {ID:"a",Tenant:"alpha",Spam:false,Score:4.5},
  {ID:"b",Tenant:"alpha",Spam:true,Score:5},
  {ID:"c",Tenant:"alpha",Spam:false,Score:8},
  {ID:"d",Tenant:"beta",Spam:false,Score:0},
  {ID:"e",Tenant:"beta",Spam:true,Score:9},
 }
}
func TestAuditThresholdStability(t *testing.T){
 a,err:=AuditThresholdStability(stabilitySamples(),5,0.5,-1)
 if err!=nil{t.Fatal(err)}
 if a.Flips!=2||a.CleanFlips!=1||a.SpamFlips!=1||len(a.Tenants)!=2{
  t.Fatalf("unexpected audit: %+v",a)
 }
 if a.Tenants[0].Tenant!="alpha"||a.Tenants[0].Flips!=2||a.Tenants[1].Tenant!="beta"||a.Tenants[1].Flips!=0{
  t.Fatalf("unexpected tenant audit: %+v",a.Tenants)
 }
 if !a.Passed{t.Fatal("descriptive audit should pass")}
 gate,err:=AuditThresholdStability(stabilitySamples(),5,0.5,0.5)
 if err!=nil{t.Fatal(err)}
 if gate.Passed||gate.Tenants[0].Passed||!gate.Tenants[1].Passed{t.Fatalf("expected alpha gate failure: %+v",gate)}
 ok,err:=AuditThresholdStability(stabilitySamples(),5,0.5,1)
 if err!=nil||!ok.Passed{t.Fatalf("expected pass: %+v %v",ok,err)}
}
func TestAuditThresholdStabilityBoundaries(t *testing.T){
 s:=[]Sample{{ID:"lower",Tenant:"t",Score:4},{ID:"upper",Tenant:"t",Score:6},{ID:"middle",Tenant:"t",Score:5}}
 a,err:=AuditThresholdStability(s,5,1,-1)
 if err!=nil{t.Fatal(err)}
 if a.Flips!=2{t.Fatalf("lower included, upper excluded: %+v",a)}
 a,err=AuditThresholdStability(s,5,0,0)
 if err!=nil||a.Flips!=0||!a.Passed{t.Fatalf("zero margin: %+v %v",a,err)}
}
func TestAuditThresholdStabilityRejectsInvalid(t *testing.T){
 for _,tc:=range []struct{name string;threshold,margin,max float64;want string}{
  {"negative margin",5,-1,-1,"margin"},
  {"NaN margin",5,math.NaN(),-1,"margin"},
  {"infinite margin",5,math.Inf(1),-1,"margin"},
  {"invalid gate",5,1,1.01,"fraction"},
  {"invalid sentinel",5,1,-0.5,"fraction"},
  {"NaN gate",5,1,math.NaN(),"fraction"},
  {"overflow",math.MaxFloat64,math.MaxFloat64,-1,"overflow"},
 }{
  t.Run(tc.name,func(t *testing.T){
   _,err:=AuditThresholdStability(stabilitySamples(),tc.threshold,tc.margin,tc.max)
   if err==nil||!strings.Contains(err.Error(),tc.want){t.Fatalf("expected %q: %v",tc.want,err)}
  })
 }
}
