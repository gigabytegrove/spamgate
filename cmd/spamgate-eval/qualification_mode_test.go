package main

import (
 "bytes"
 "crypto/sha256"
 "encoding/hex"
 "encoding/json"
 "fmt"
 "os"
 "path/filepath"
 "strings"
 "testing"
)

func qualificationArgs(path,digest string) []string {
 return []string{
  "--qualification-mode","--require-unique-ids","--require-cohorts",
  "--corpus-sha256="+digest,
  "--min-ham=100","--min-spam=100",
  "--max-fpr-upper=0.1","--min-recall-lower=0.8",
  "--min-precision-lower=0.8","--max-reject-fpr-upper=0.1",
  "--max-disruptive-fpr-upper=0.1",
  "--max-cohort-fpr-upper=0.1","--min-cohort-recall-lower=0.8",
  "--min-cohort-precision-lower=0.8",
  "--max-cohort-reject-fpr-upper=0.1",
  "--max-cohort-disruptive-fpr-upper=0.1",
  path,
 }
}

func TestQualificationModeRequiresIntegrityAndExplicitGates(t *testing.T) {
 for _,args:=range [][]string{
  {"--qualification-mode","missing.jsonl"},
  {"--qualification-mode","--require-unique-ids","--require-cohorts","--corpus-sha256="+strings.Repeat("0",64),"missing.jsonl"},
 } {
  var out,errout bytes.Buffer
  if got:=run(args,&out,&errout);got!=2 {t.Fatalf("expected usage error, got %d: %s",got,errout.String())}
  if out.Len()!=0 {t.Fatalf("unexpected qualification output: %s",out.String())}
 }
}

func TestQualificationModeValidatesDisjointIntegrityBoundCorpus(t *testing.T) {
 var corpus strings.Builder
 for _,cohort:=range []string{"direct","forwarded"} {
  for _,label:=range []string{"ham","spam"} {
   for i:=0;i<1000;i++ {
    digest:=sha256.Sum256([]byte(fmt.Sprintf("%s/%s/%d",cohort,label,i)))
    action:="accept"
    if label=="spam" {action="reject"}
    fmt.Fprintf(&corpus,"{\"id\":%q,\"label\":%q,\"action\":%q,\"cohort\":%q}\n",hex.EncodeToString(digest[:]),label,action,cohort)
   }
  }
 }
 path:=filepath.Join(t.TempDir(),"corpus.jsonl")
 data:=[]byte(corpus.String())
 if err:=os.WriteFile(path,data,0600);err!=nil {t.Fatal(err)}
 digest:=sha256.Sum256(data)
 args:=qualificationArgs(path,hex.EncodeToString(digest[:]))
 var out,errout bytes.Buffer
 if got:=run(args,&out,&errout);got!=0 {t.Fatalf("qualified corpus failed: %d %s",got,errout.String())}
 var result report
 if err:=json.Unmarshal(out.Bytes(),&result);err!=nil {t.Fatal(err)}
 if !result.GatePassed||!result.CohortGatePassed||len(result.Cohorts)!=2 {t.Fatalf("unexpected result: %+v",result)}
 args[3]="--corpus-sha256="+strings.Repeat("0",64)
 out.Reset();errout.Reset()
 if got:=run(args,&out,&errout);got!=2 {t.Fatalf("accepted tampered digest: %d %s",got,errout.String())}
}
