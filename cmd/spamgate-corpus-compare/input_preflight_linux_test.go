package main

import (
 "os"
 "path/filepath"
 "strings"
 "syscall"
 "testing"
)

func TestEvidenceOpenNoFollowKernelEnforcement(t *testing.T) {
 dir:=t.TempDir()
 target:=filepath.Join(dir,"target")
 alias:=filepath.Join(dir,"alias")
 if err:=os.WriteFile(target,[]byte("safe"),0600);err!=nil{t.Fatal(err)}
 if err:=os.Symlink(target,alias);err!=nil{t.Fatal(err)}
 fd,err:=syscall.Open(alias,syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC|syscall.O_NONBLOCK,0)
 if err==nil {syscall.Close(fd);t.Fatal("O_NOFOLLOW followed a symlink")}
 f,err:=openEvidence(alias)
 if f!=nil {f.Close()}
 if err==nil {t.Fatal("openEvidence followed a symlink")}
}

func TestEvidenceOpenRejectsFIFOWithoutBlocking(t *testing.T) {
 dir:=t.TempDir()
 fifo:=filepath.Join(dir,"fifo")
 if err:=syscall.Mkfifo(fifo,0600);err!=nil{t.Fatal(err)}
 f,err:=openEvidence(fifo)
 if f!=nil {f.Close()}
 if err==nil||!strings.Contains(err.Error(),"regular file"){t.Fatalf("FIFO accepted or unexpected error: %v",err)}
}

func TestEvidenceOpenPreservesInodeIdentity(t *testing.T) {
 dir:=t.TempDir()
 path:=filepath.Join(dir,"sample")
 if err:=os.WriteFile(path,[]byte("evidence"),0600);err!=nil{t.Fatal(err)}
 before,err:=os.Lstat(path);if err!=nil{t.Fatal(err)}
 f,err:=openEvidence(path);if err!=nil{t.Fatal(err)}
 defer f.Close()
 after,err:=f.Stat();if err!=nil{t.Fatal(err)}
 if !os.SameFile(before,after){t.Fatal("opened inode does not match inspected inode")}
}
