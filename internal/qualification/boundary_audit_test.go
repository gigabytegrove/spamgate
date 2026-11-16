package qualification

import (
 "math"
 "testing"
)
func TestAuditBoundaryTenantCounts(t *testing.T) {
 samples:=[]Sample{
  {ID:"1",Tenant:"z",Spam:true,Score:5},
  {ID:"2",Tenant:"z",Spam:false,Score:5.1},
  {ID:"3",Tenant:"a",Spam:false,Score:4.9},
  {ID:"4",Tenant:"a",Spam:true,Score:8},
 }
 got,err:=AuditBoundary(samples,5,0.11)
 if err!=nil {t.Fatal(err)}
 if got.TotalNear!=3||got.ExactTies!=1||len(got.Tenants)!=2 {t.Fatalf("unexpected audit: %+v",got)}
 if got.Tenants[0].Tenant!="a"||got.Tenants[0].Near!=1||got.Tenants[0].CleanNear!=1||got.Tenants[0].NearFraction!=0.5 {t.Fatalf("tenant a: %+v",got.Tenants[0])}
 if got.Tenants[1].Tenant!="z"||got.Tenants[1].Near!=2||got.Tenants[1].ExactTies!=1 {t.Fatalf("tenant z: %+v",got.Tenants[1])}
}
func TestAuditBoundaryRejectsInvalidInput(t *testing.T) {
 samples:=[]Sample{{ID:"1",Tenant:"a",Score:5}}
 for _,margin:=range []float64{-1,math.NaN(),math.Inf(1),math.Inf(-1)} {
  if _,err:=AuditBoundary(samples,5,margin);err==nil {t.Fatalf("accepted margin %v",margin)}
 }
 if _,err:=AuditBoundary(samples,math.NaN(),1);err==nil {t.Fatal("accepted invalid threshold")}
 if _,err:=AuditBoundary(nil,5,1);err==nil {t.Fatal("accepted empty corpus")}
}
func TestAuditBoundaryZeroMarginAndOverflow(t *testing.T) {
 samples:=[]Sample{{ID:"1",Tenant:"a",Score:math.MaxFloat64},{ID:"2",Tenant:"a",Score:-math.MaxFloat64}}
 got,err:=AuditBoundary(samples,math.MaxFloat64,0)
 if err!=nil {t.Fatal(err)}
 if got.TotalNear!=1||got.ExactTies!=1 {t.Fatalf("wrong zero-margin audit: %+v",got)}
}
