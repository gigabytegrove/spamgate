package qualification

import (
 "reflect"
 "testing"
)
func TestAuditCorpusTenantComposition(t *testing.T) {
 samples:=[]Sample{
  {ID:"1",Tenant:"z",Spam:true,Score:10},
  {ID:"2",Tenant:"a",Spam:false,Score:0},
  {ID:"3",Tenant:"z",Spam:false,Score:2},
 }
 got,err:=AuditCorpus(samples)
 if err!=nil {t.Fatal(err)}
 if got.Total!=3||got.Spam!=1||got.Clean!=2 {t.Fatalf("wrong totals: %+v",got)}
 if !reflect.DeepEqual([]string{got.Tenants[0].Tenant,got.Tenants[1].Tenant},[]string{"a","z"}) {t.Fatalf("not sorted: %+v",got.Tenants)}
 if got.Tenants[1].SpamPrevalence!=0.5 {t.Fatalf("wrong prevalence: %+v",got.Tenants[1])}
}
func TestAuditCorpusRejectsDuplicateIDs(t *testing.T) {
 _,err:=AuditCorpus([]Sample{{ID:"duplicate",Tenant:"a"},{ID:"duplicate",Tenant:"b"}})
 if err==nil {t.Fatal("duplicate accepted")}
}
func TestAuditCorpusRejectsEmpty(t *testing.T) {
 if _,err:=AuditCorpus(nil);err==nil {t.Fatal("empty corpus accepted")}
}
