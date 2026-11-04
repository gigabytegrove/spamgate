package main

import (
 "bytes"
 "crypto/sha256"
 "encoding/hex"
 "os"
 "path/filepath"
 "strings"
 "testing"
)

func TestCorpusSHA256IntegrityGate(t *testing.T) {
 path:=filepath.Join(t.TempDir(),"labels.jsonl")
 data:=[]byte("{\"label\":\"ham\",\"action\":\"accept\"}\n{\"label\":\"spam\",\"action\":\"reject\"}\n")
 if err:=os.WriteFile(path,data,0600);err!=nil{t.Fatal(err)}
 digest:=sha256.Sum256(data)
 correct:=hex.EncodeToString(digest[:])
 base:=[]string{"--min-ham=1","--min-spam=1","--max-fpr-upper=1","--min-recall-lower=0"}
 for _,tc:=range []struct{name,digest string;want int}{
  {"matching",correct,0},
  {"mismatch",strings.Repeat("0",64),2},
  {"uppercase",strings.ToUpper(correct),2},
  {"short","1234",2},
  {"nonhex",strings.Repeat("g",64),2},
 }{
  t.Run(tc.name,func(t *testing.T){
   var out,errout bytes.Buffer
   args:=append(append([]string{},base...),"--corpus-sha256="+tc.digest,path)
   code:=run(args,&out,&errout)
   if code!=tc.want {t.Fatalf("code=%d want=%d stderr=%s",code,tc.want,errout.String())}
   if code!=0 && out.Len()!=0 {t.Fatalf("invalid provenance produced report: %s",out.String())}
  })
 }
 // A valid prefix must not qualify when the file has been appended to.
 appended:=append(append([]byte{},data...),[]byte("\n  \n")...)
 if err:=os.WriteFile(path,appended,0600);err!=nil{t.Fatal(err)}
 var out,errout bytes.Buffer
 if code:=run(append(append([]string{},base...),"--corpus-sha256="+correct,path),&out,&errout);code!=2||out.Len()!=0{
  t.Fatalf("appended corpus qualified: code=%d out=%s err=%s",code,out.String(),errout.String())
 }
}
