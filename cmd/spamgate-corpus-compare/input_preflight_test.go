package main

import (
 "os"
 "path/filepath"
 "strings"
 "testing"
)

func TestOpenEvidencePairDistinctRegularFiles(t *testing.T) {
 dir:=t.TempDir()
 a:=filepath.Join(dir,"a.jsonl"); b:=filepath.Join(dir,"b.jsonl")
 for _,p:=range []string{a,b} { if err:=os.WriteFile(p,[]byte("{\"id\":\"x\"}\n"),0600);err!=nil{t.Fatal(err)} }
 af,bf,err:=openEvidencePair(a,b);if err!=nil{t.Fatal(err)}
 defer af.Close();defer bf.Close()
}
func TestOpenEvidencePairRejectsSameFileAndHardlink(t *testing.T) {
 dir:=t.TempDir();a:=filepath.Join(dir,"a");b:=filepath.Join(dir,"b")
 if err:=os.WriteFile(a,[]byte("data"),0600);err!=nil{t.Fatal(err)}
 if err:=os.Link(a,b);err!=nil{t.Skipf("hardlinks unavailable: %v",err)}
 for _,pair:=range [][2]string{{a,a},{a,b}} {
  x,y,err:=openEvidencePair(pair[0],pair[1])
  if x!=nil {x.Close()};if y!=nil{y.Close()}
  if err==nil||!strings.Contains(err.Error(),"same file"){t.Fatalf("pair %q: %v",pair,err)}
 }
}
func TestOpenEvidenceRejectsSymlinkAndDirectory(t *testing.T) {
 dir:=t.TempDir();target:=filepath.Join(dir,"target");link:=filepath.Join(dir,"link")
 if err:=os.WriteFile(target,[]byte("data"),0600);err!=nil{t.Fatal(err)}
 if err:=os.Symlink(target,link);err!=nil{t.Skipf("symlink unavailable: %v",err)}
 for _,p:=range []string{link,dir} {
  f,err:=openEvidence(p);if f!=nil{f.Close()}
  if err==nil {t.Fatalf("accepted nonregular %q",p)}
 }
}
func TestOpenEvidenceMissing(t *testing.T) {
 f,err:=openEvidence(filepath.Join(t.TempDir(),"missing"))
 if f!=nil {f.Close()}
 if err==nil {t.Fatal("missing evidence accepted")}
}
