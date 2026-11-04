//go:build linux

package main

import (
 "os"
 "path/filepath"
 "testing"
 "time"
)

func TestCorpusChangeTimeDetectsRestoredMtimeAndSize(t *testing.T) {
 path:=filepath.Join(t.TempDir(),"labels.jsonl")
 if err:=os.WriteFile(path,[]byte("original"),0600);err!=nil{t.Fatal(err)}
 old:=time.Unix(1600000000,0)
 if err:=os.Chtimes(path,old,old);err!=nil{t.Fatal(err)}
 f,initial,err:=openEvaluationCorpus(path)
 if err!=nil{t.Fatal(err)}
 defer f.Close()
 if err:=verifyEvaluationCorpusUnchanged(f,initial);err!=nil{t.Fatal(err)}
 // Rewriting equal-length bytes and restoring mtime must still be caught.
 if err:=os.WriteFile(path,[]byte("modified"),0600);err!=nil{t.Fatal(err)}
 if err:=os.Chtimes(path,old,old);err!=nil{t.Fatal(err)}
 current,err:=f.Stat()
 if err!=nil{t.Fatal(err)}
 if current.Size()!=initial.Size() || !current.ModTime().Equal(initial.ModTime()){
  t.Fatal("fixture did not restore size and mtime")
 }
 if evaluationCorpusChangeTimeEqual(initial,current){t.Fatal("Linux inode change time did not detect modification")}
 if err:=verifyEvaluationCorpusUnchanged(f,initial);err==nil{t.Fatal("restored mtime bypassed descriptor verification")}
 if err:=verifyEvaluationCorpusPathUnchanged(path,initial);err==nil{t.Fatal("restored mtime bypassed pathname verification")}
}
