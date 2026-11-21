package main

import (
 "bytes"
 "encoding/json"
 "os"
 "path/filepath"
 "strings"
 "testing"
)

func TestTenantComparisonAndDrift(t *testing.T) {
 baseline:=`{"id":"a","tenant":"north","truth":"clean","score":0.1}
{"id":"b","tenant":"north","truth":"spam","score":0.9}
{"id":"c","tenant":"south","truth":"clean","score":0.1}
{"id":"d","tenant":"south","truth":"spam","score":0.9}
`
 candidate:=`{"id":"a","tenant":"north","truth":"clean","score":0.9}
{"id":"b","tenant":"north","truth":"spam","score":0.9}
{"id":"c","tenant":"south","truth":"clean","score":0.1}
{"id":"d","tenant":"south","truth":"spam","score":0.9}
`
 b,err:=loadCorpus(strings.NewReader(baseline));if err!=nil{t.Fatal(err)}
 c,err:=loadCorpus(strings.NewReader(candidate));if err!=nil{t.Fatal(err)}
 r,err:=compareCorpora(b,c,0.5);if err!=nil{t.Fatal(err)}
 if len(r.ByTenant)!=2||r.ByTenant["north"].NewFalsePositives!=1||r.ByTenant["south"].CandidateFalsePositives!=0 {t.Fatalf("tenant evidence: %+v",r.ByTenant)}
 if tenantGatesPass(r.ByTenant,0,1,1,1) {t.Fatal("global average hid tenant regression")}
 if !tenantGatesPass(r.ByTenant,1,1,1,1) {t.Fatal("permissive tenant gates failed")}
 altered:=c["a"];altered.Tenant="south";c["a"]=altered
 if _,err:=compareCorpora(b,c,0.5);err==nil {t.Fatal("tenant drift accepted")}
}
func TestTenantCLIQualification(t *testing.T) {
 dir:=t.TempDir()
 base:=filepath.Join(dir,"base.jsonl");candidate:=filepath.Join(dir,"candidate.jsonl")
 samples:=`{"id":"a","tenant":"north","truth":"clean","score":0.1}
{"id":"b","tenant":"north","truth":"spam","score":0.9}
`
 for _,path:=range []string{base,candidate} {if err:=os.WriteFile(path,[]byte(samples),0600);err!=nil{t.Fatal(err)}}
 args:=[]string{"-baseline",base,"-candidate",candidate,"-require-tenants","-min-tenant-clean=1","-min-tenant-spam=1"}
 var out,errs bytes.Buffer
 if code:=compareRun(args,&out,&errs);code!=0 {t.Fatalf("valid tenant corpus code %d: %s",code,errs.String())}
 var report comparisonReport
 if err:=json.Unmarshal(out.Bytes(),&report);err!=nil{t.Fatal(err)}
 if report.ByTenant["north"].Clean!=1 {t.Fatal("missing tenant report")}
 out.Reset();errs.Reset()
 if code:=compareRun(append(append([]string{},args...),"-min-tenant-clean=2"),&out,&errs);code!=1 {t.Fatalf("undersized tenant corpus code %d",code)}
 out.Reset();errs.Reset()
 if code:=compareRun(append(append([]string{},args...),"-max-tenant-fpr-upper-95=0"),&out,&errs);code!=1 {t.Fatalf("confidence gate code %d",code)}
 out.Reset();errs.Reset()
 if code:=compareRun(append(append([]string{},args...),"-max-tenant-fnr=NaN"),&out,&errs);code!=2 {t.Fatalf("nonfinite gate code %d",code)}
}
func TestTenantMissingAndDuplicateEvidence(t *testing.T) {
 for _,raw:=range []string{
  `{"id":"a","tenant":"north","tenant":"south","truth":"clean","score":0.1}`,
  `{"id":"a","tenant":null,"truth":"clean","score":0.1}`,
  `{"id":"a","tenant":3,"truth":"clean","score":0.1}`,
 } {if _,err:=decodeSample(raw);err==nil{t.Fatalf("accepted invalid tenant: %s",raw)}}
}
