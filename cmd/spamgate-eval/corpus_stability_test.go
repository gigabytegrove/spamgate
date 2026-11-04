package main

import (
 "os"
 "path/filepath"
 "strings"
 "testing"
 "time"
)

func TestEvaluationCorpusRequiresRegularFile(t *testing.T) {
 dir:=t.TempDir()
 regular:=filepath.Join(dir,"labels.jsonl")
 if err:=os.WriteFile(regular,[]byte("{\"label\":\"ham\",\"action\":\"accept\"}\n{\"label\":\"spam\",\"action\":\"reject\"}\n"),0600);err!=nil{t.Fatal(err)}
 f,initial,err:=openEvaluationCorpus(regular)
 if err!=nil{t.Fatal(err)}
 if err:=verifyEvaluationCorpusUnchanged(f,initial);err!=nil{t.Fatal(err)}
 f.Close()
 link:=filepath.Join(dir,"link.jsonl")
 if err:=os.Symlink(regular,link);err!=nil{t.Fatal(err)}
 for _,path:=range []string{dir,link} {
  if f,_,err:=openEvaluationCorpus(path);err==nil {f.Close();t.Fatalf("nonregular path accepted: %s",path)}
 }
}

func TestEvaluationCorpusDetectsInPlaceChangeAndReplacement(t *testing.T) {
 dir:=t.TempDir()
 path:=filepath.Join(dir,"corpus")
 if err:=os.WriteFile(path,[]byte("original"),0600);err!=nil{t.Fatal(err)}
 f,initial,err:=openEvaluationCorpus(path)
 if err!=nil{t.Fatal(err)}
 defer f.Close()
 if err:=os.WriteFile(path,[]byte("longer modified corpus"),0600);err!=nil{t.Fatal(err)}
 if err:=verifyEvaluationCorpusUnchanged(f,initial);err==nil{t.Fatal("in-place mutation accepted")}
 if err:=os.Remove(path);err!=nil{t.Fatal(err)}
 if err:=os.WriteFile(path,[]byte("replacement"),0600);err!=nil{t.Fatal(err)}
 if err:=verifyEvaluationCorpusUnchanged(f,initial);err==nil{t.Fatal("replacement not detected after size change")}
}

func TestEvaluationCorpusMutationPreventsReport(t *testing.T) {
 dir:=t.TempDir()
 path:=filepath.Join(dir,"corpus")
 if err:=os.WriteFile(path,[]byte("before"),0600);err!=nil{t.Fatal(err)}
 f,info,err:=openEvaluationCorpus(path)
 if err!=nil{t.Fatal(err)}
 defer f.Close()
 // Explicit mtime change catches same-size rewrites on normal filesystems.
 if err:=os.WriteFile(path,[]byte("after!"),0600);err!=nil{t.Fatal(err)}
 changed:=info.ModTime().Add(2*time.Second)
 if err:=os.Chtimes(path,changed,changed);err!=nil{t.Fatal(err)}
 if err:=verifyEvaluationCorpusUnchanged(f,info);err==nil{t.Fatal("same-size changed corpus accepted")}
 if _,_,err:=openEvaluationCorpus(strings.Repeat("x",1)+filepath.Join(dir,"missing"));err==nil{t.Fatal("missing file accepted")}
}
