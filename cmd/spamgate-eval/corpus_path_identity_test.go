package main

import (
 "os"
 "path/filepath"
 "strings"
 "testing"
 "time"
)

func TestEvaluationCorpusPathReplacementWithIdenticalMetadata(t *testing.T) {
 dir:=t.TempDir()
 path:=filepath.Join(dir,"labels.jsonl")
 original:=[]byte("same-sized corpus content")
 if err:=os.WriteFile(path,original,0600);err!=nil {t.Fatal(err)}
 f,initial,err:=openEvaluationCorpus(path)
 if err!=nil {t.Fatal(err)}
 defer f.Close()
 replacement:=filepath.Join(dir,"replacement")
 if err:=os.WriteFile(replacement,[]byte(strings.Repeat("X",len(original))),0600);err!=nil {t.Fatal(err)}
 // Matching timestamps and byte counts must not bypass inode identity.
 stamp:=initial.ModTime()
 if err:=os.Chtimes(replacement,stamp,stamp);err!=nil {t.Fatal(err)}
 if err:=os.Rename(replacement,path);err!=nil {t.Fatal(err)}
 if err:=verifyEvaluationCorpusUnchanged(f,initial);err!=nil {t.Fatalf("descriptor unexpectedly changed: %v",err)}
 if err:=verifyEvaluationCorpusPathUnchanged(path,initial);err==nil {t.Fatal("same-size same-mtime pathname replacement accepted")}
}

func TestEvaluationCorpusPathUnlinkAndSymlinkRefused(t *testing.T) {
 dir:=t.TempDir()
 path:=filepath.Join(dir,"labels.jsonl")
 if err:=os.WriteFile(path,[]byte("labels"),0600);err!=nil {t.Fatal(err)}
 f,initial,err:=openEvaluationCorpus(path)
 if err!=nil {t.Fatal(err)}
 defer f.Close()
 if err:=verifyEvaluationCorpusPathUnchanged(path,initial);err!=nil {t.Fatal(err)}
 if err:=os.Remove(path);err!=nil {t.Fatal(err)}
 if err:=verifyEvaluationCorpusPathUnchanged(path,initial);err==nil {t.Fatal("unlinked corpus accepted")}
 if err:=os.Symlink(filepath.Join(dir,"missing"),path);err!=nil {t.Fatal(err)}
 if err:=verifyEvaluationCorpusPathUnchanged(path,initial);err==nil {t.Fatal("symlink replacement accepted")}
}

func TestEvaluationCorpusPathDetectsSameInodeMetadataChange(t *testing.T) {
 dir:=t.TempDir()
 path:=filepath.Join(dir,"labels.jsonl")
 if err:=os.WriteFile(path,[]byte("labels"),0600);err!=nil {t.Fatal(err)}
 f,initial,err:=openEvaluationCorpus(path)
 if err!=nil {t.Fatal(err)}
 defer f.Close()
 stamp:=initial.ModTime().Add(3*time.Second)
 if err:=os.Chtimes(path,stamp,stamp);err!=nil {t.Fatal(err)}
 if err:=verifyEvaluationCorpusPathUnchanged(path,initial);err==nil {t.Fatal("metadata mutation accepted")}
}
