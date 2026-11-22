package main

import (
 "bytes"
 "os"
 "path/filepath"
 "strings"
 "testing"
)

// Identical bytes in independently captured reports are permitted; reusing
// the same inode is not an independent observation.
func TestTrendRejectsAliasedEvidence(t *testing.T) {
 dir:=t.TempDir()
 before:=filepath.Join(dir,"before.json")
 after:=filepath.Join(dir,"after.json")
 data:=[]byte(`{"gate_passed":true,"examined":0,"published":0,"pending":0,"states":{},"findings":[],"truncated":false}`)
 if err:=os.WriteFile(before,data,0600);err!=nil{t.Fatal(err)}
 if err:=os.Link(before,after);err!=nil{t.Skipf("hardlinks unsupported: %v",err)}
 var out,diagnostics bytes.Buffer
 status:=run([]string{"-before",before,"-after",after},&out,&diagnostics)
 if status!=2 || out.Len()!=0 || !strings.Contains(diagnostics.String(),"same file") {
  t.Fatalf("status=%d stdout=%q stderr=%q",status,out.String(),diagnostics.String())
 }
}

func TestTrendDistinctFilesRemainIndependent(t *testing.T) {
 dir:=t.TempDir()
 before:=filepath.Join(dir,"before.json")
 after:=filepath.Join(dir,"after.json")
 data:=[]byte(`{"gate_passed":true,"examined":0,"published":0,"pending":0,"states":{},"findings":[],"truncated":false}`)
 for _,path:=range []string{before,after} {
  if err:=os.WriteFile(path,data,0600);err!=nil{t.Fatal(err)}
 }
 var out,diagnostics bytes.Buffer
 status:=run([]string{"-before",before,"-after",after},&out,&diagnostics)
 if status!=0 || !strings.Contains(out.String(),`"gate_passed": true`) {
  t.Fatalf("status=%d stdout=%q stderr=%q",status,out.String(),diagnostics.String())
 }
}
