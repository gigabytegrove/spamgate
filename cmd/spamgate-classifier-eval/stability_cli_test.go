package main

import (
 "bytes"
 "encoding/json"
 "strings"
 "testing"
)

const stabilityCorpus = `[
 {"id":"a","tenant":"alpha","spam":false,"score":4.5},
 {"id":"b","tenant":"alpha","spam":true,"score":5},
 {"id":"c","tenant":"alpha","spam":false,"score":8},
 {"id":"d","tenant":"beta","spam":false,"score":0},
 {"id":"e","tenant":"beta","spam":true,"score":9}
]`

func TestStabilityCLIReportAndGate(t *testing.T){
 var out bytes.Buffer
 err:=run([]string{"-stability-margin=0.5","-max-stability-flips=0.5"},strings.NewReader(stabilityCorpus),&out)
 if err==nil||!strings.Contains(err.Error(),"qualification gates failed"){t.Fatalf("expected gate failure: %v",err)}
 var report struct{StabilityAudit struct{Passed bool `json:"passed"`;Flips int `json:"flips"`;Tenants []struct{Tenant string `json:"tenant"`;Passed bool `json:"passed"`} `json:"tenants"`} `json:"stability_audit"`}
 if err:=json.Unmarshal(out.Bytes(),&report);err!=nil{t.Fatalf("missing audit: %v, %q",err,out.String())}
 if report.StabilityAudit.Passed||report.StabilityAudit.Flips!=2||len(report.StabilityAudit.Tenants)!=2||report.StabilityAudit.Tenants[0].Passed{t.Fatalf("unexpected gate: %+v",report)}
 out.Reset()
 err=run([]string{"-stability-margin=0.5"},strings.NewReader(stabilityCorpus),&out)
 if err!=nil{t.Fatalf("descriptive audit: %v",err)}
 if !bytes.Contains(out.Bytes(),[]byte(`"stability_audit"`)){t.Fatalf("missing audit: %s",out.String())}
}
func TestStabilityCLIInvalidOptionsNoReport(t *testing.T){
 for _,args:=range [][]string{
  {"-max-stability-flips=0.1"},
  {"-stability-margin=-1"},
  {"-stability-margin=NaN"},
  {"-stability-margin=0.5","-max-stability-flips=-1"},
  {"-stability-margin=0.5","-max-stability-flips=1.01"},
 }{
  var out bytes.Buffer
  err:=run(args,strings.NewReader(stabilityCorpus),&out)
  if err==nil{t.Fatalf("expected rejection for %v",args)}
  if out.Len()!=0{t.Fatalf("invalid flags emitted report for %v: %q",args,out.String())}
 }
}
