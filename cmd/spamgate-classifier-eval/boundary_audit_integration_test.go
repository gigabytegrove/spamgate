package main

import (
 "bytes"
 "encoding/json"
 "strings"
 "testing"
)
func TestBoundaryAuditCLI(t *testing.T) {
 corpus:=`[{"id":"1","tenant":"b","spam":true,"score":5},{"id":"2","tenant":"a","spam":false,"score":4.9},{"id":"3","tenant":"a","spam":false,"score":0}]`
 var out bytes.Buffer
 if err:=run([]string{"-threshold=5","-audit-boundary-margin=0.11"},strings.NewReader(corpus),&out);err!=nil {t.Fatal(err)}
 var report struct {
  BoundaryAudit struct {
   TotalNear int `json:"total_near"`
   ExactTies int `json:"exact_ties"`
   Tenants []struct{Tenant string `json:"tenant"`;Near int `json:"near"`} `json:"tenants"`
  } `json:"boundary_audit"`
 }
 if err:=json.Unmarshal(out.Bytes(),&report);err!=nil {t.Fatal(err)}
 if report.BoundaryAudit.TotalNear!=2||report.BoundaryAudit.ExactTies!=1||len(report.BoundaryAudit.Tenants)!=2 {t.Fatalf("unexpected report: %s",out.String())}
 if report.BoundaryAudit.Tenants[0].Tenant!="a"||report.BoundaryAudit.Tenants[0].Near!=1 {t.Fatalf("wrong tenant ordering: %s",out.String())}
}
func TestBoundaryAuditCLIInvalidThreshold(t *testing.T) {
 var out bytes.Buffer
 corpus:=`[{"id":"1","tenant":"a","spam":true,"score":5}]`
 if err:=run([]string{"-threshold=NaN","-audit-boundary-margin=1"},strings.NewReader(corpus),&out);err==nil {t.Fatal("accepted NaN threshold")}
}
