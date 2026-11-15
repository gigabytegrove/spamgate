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

func TestQualificationEvidenceDoesNotClaimUnverifiedDigest(t *testing.T) {
 e:=qualificationEvidenceForRun(false,false,false,"",24,1024,100)
 if e.Mode||e.CorpusDigestVerified||e.CorpusSHA256!=""||e.EvaluatedRecords!=24 {
  t.Fatalf("unverified evaluation misrepresented: %+v",e)
 }
 raw,err:=json.Marshal(e)
 if err!=nil{t.Fatal(err)}
 if bytes.Contains(raw,[]byte("corpus_sha256")){t.Fatalf("unverified digest emitted: %s",raw)}
}

func TestQualificationEvidenceBoundToVerifiedCorpus(t *testing.T) {
 var b strings.Builder
 for _,cohort:=range []string{"direct","forwarded"} {
  for _,label:=range []string{"ham","spam"} {
   for i:=0;i<1000;i++ {
    id:=sha256.Sum256([]byte(fmt.Sprintf("%s/%s/%d",cohort,label,i)))
    action:="accept"
    if label=="spam"{action="reject"}
    fmt.Fprintf(&b,"{\"id\":%q,\"label\":%q,\"action\":%q,\"cohort\":%q}\n",hex.EncodeToString(id[:]),label,action,cohort)
   }
  }
 }
 data:=[]byte(b.String())
 digest:=sha256.Sum256(data)
 expected:=hex.EncodeToString(digest[:])
 path:=filepath.Join(t.TempDir(),"labels.jsonl")
 if err:=os.WriteFile(path,data,0600);err!=nil{t.Fatal(err)}
 var out,errs bytes.Buffer
 if got:=run(qualificationArgs(path,expected),&out,&errs);got!=0{t.Fatalf("qualification failed: %d %s",got,errs.String())}
 var r report
 if err:=json.Unmarshal(out.Bytes(),&r);err!=nil{t.Fatal(err)}
 e:=r.Qualification
 if !e.Mode||!e.UniqueIDsRequired||!e.CohortsRequired||!e.CorpusDigestVerified||e.CorpusSHA256!=expected||e.EvaluatedRecords!=4000||!r.GatePassed {
  t.Fatalf("missing provenance: %+v",e)
 }
 if strings.Contains(out.String(),path){t.Fatal("report leaked corpus path")}
}

func TestQualificationEvidenceTamperedDigestNeverEmitted(t *testing.T) {
 e:=qualificationEvidenceForRun(true,true,true,"",0,1024,100)
 if e.CorpusDigestVerified||e.CorpusSHA256!=""{t.Fatal("unverified corpus marked verified")}
}
