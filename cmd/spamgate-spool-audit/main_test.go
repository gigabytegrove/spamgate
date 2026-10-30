package main

import (
 "bytes"
 "os"
 "path/filepath"
 "strings"
 "testing"
)
func TestCLIReadOnlyAndExitCodes(t *testing.T){
 dir:=filepath.Join(t.TempDir(),"delivery-queue")
 if err:=os.Mkdir(dir,0700);err!=nil{t.Fatal(err)}
 var out,stderr bytes.Buffer
 if code:=run([]string{"-dir",dir,"-json"},&out,&stderr);code!=0||!strings.Contains(out.String(),"\"published\": 0"){
  t.Fatalf("clean exit=%d out=%s err=%s",code,out.String(),stderr.String())
 }
 if err:=os.WriteFile(filepath.Join(dir,".pending-incomplete"),[]byte("bad"),0600);err!=nil{t.Fatal(err)}
 out.Reset();stderr.Reset()
 if code:=run([]string{"-dir",dir},&out,&stderr);code!=1||!strings.Contains(out.String(),"unreadable_record"){
  t.Fatalf("warning exit=%d out=%s err=%s",code,out.String(),stderr.String())
 }
 out.Reset();stderr.Reset()
 if code:=run([]string{"-dir",filepath.Join(dir,"missing")},&out,&stderr);code!=2{
  t.Fatalf("missing directory exit=%d",code)
 }
 out.Reset();stderr.Reset()
 if code:=run([]string{"-unknown"},&out,&stderr);code!=2{
  t.Fatalf("invalid flags exit=%d",code)
 }
}
