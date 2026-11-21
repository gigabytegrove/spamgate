//go:build linux

package spooltrend

import (
 "os"
 "path/filepath"
 "syscall"
 "testing"
 "time"
)

func TestOpenEvidenceRejectsFinalSymlink(t *testing.T) {
 dir := t.TempDir()
 target := filepath.Join(dir,"target")
 if err := os.WriteFile(target,[]byte("safe"),0600); err != nil { t.Fatal(err) }
 link := filepath.Join(dir,"link")
 if err := os.Symlink(target,link); err != nil { t.Fatal(err) }
 if f,err := openEvidence(link); err == nil {
  f.Close()
  t.Fatal("opened final-component symlink")
 }
}

func TestOpenEvidenceDoesNotBlockOnFIFO(t *testing.T) {
 dir := t.TempDir()
 fifo := filepath.Join(dir,"fifo")
 if err := syscall.Mkfifo(fifo,0600); err != nil { t.Fatal(err) }
 done := make(chan error,1)
 go func() {
  f,err := openEvidence(fifo)
  if err == nil { f.Close() }
  done <- err
 }()
 select {
 case <-done:
 case <-time.After(2*time.Second):
  t.Fatal("opening substituted FIFO blocked")
 }
 if _,err := Load(fifo); err == nil { t.Fatal("accepted FIFO as evidence") }
}

func TestOpenEvidenceRegularFile(t *testing.T) {
 dir := t.TempDir()
 path := filepath.Join(dir,"report")
 if err := os.WriteFile(path,[]byte("ok"),0600); err != nil { t.Fatal(err) }
 f,err := openEvidence(path)
 if err != nil { t.Fatal(err) }
 defer f.Close()
 info,err := f.Stat()
 if err != nil || !info.Mode().IsRegular() { t.Fatalf("not regular: %v %v",info,err) }
}
