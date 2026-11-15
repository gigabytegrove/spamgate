//go:build linux

package backup

import (
 "os"
 "path/filepath"
 "syscall"
 "testing"
)

func TestOpenRestoredRegularNoFollowRejectsSpecialLeaves(t *testing.T) {
 root := t.TempDir()
 fifo := filepath.Join(root, "mail.fifo")
 if err := syscall.Mkfifo(fifo, 0600); err != nil { t.Fatal(err) }
 if f, err := openRestoredRegularNoFollow(fifo); err == nil {
  _ = f.Close()
  t.Fatal("FIFO accepted as restored file")
 }
 dir := filepath.Join(root, "maildir")
 if err := os.Mkdir(dir, 0700); err != nil { t.Fatal(err) }
 if f, err := openRestoredRegularNoFollow(dir); err == nil {
  _ = f.Close()
  t.Fatal("directory accepted as restored file")
 }
}

func TestOpenRestoredRegularNoFollowReturnsReadableRegularFile(t *testing.T) {
 root := t.TempDir()
 name := filepath.Join(root, "message.eml")
 want := []byte("Subject: restore verification\r\n\r\nbody\r\n")
 if err := os.WriteFile(name, want, 0600); err != nil { t.Fatal(err) }
 f, err := openRestoredRegularNoFollow(name)
 if err != nil { t.Fatal(err) }
 defer f.Close()
 got := make([]byte, len(want))
 if n, err := f.Read(got); err != nil || n != len(want) { t.Fatalf("read n=%d err=%v", n, err) }
 if string(got) != string(want) { t.Fatalf("unexpected contents %q", got) }
}
