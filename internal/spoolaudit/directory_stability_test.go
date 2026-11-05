package spoolaudit

import (
 "os"
 "path/filepath"
 "strings"
 "testing"
)

func TestVerifyAuditDirectoryPathStable(t *testing.T) {
 dir := privateDir(t)
 f, err := os.Open(dir)
 if err != nil { t.Fatal(err) }
 defer f.Close()
 opened, err := f.Stat()
 if err != nil { t.Fatal(err) }
 if err := verifyAuditDirectoryPath(dir, opened); err != nil { t.Fatal(err) }
}

func TestVerifyAuditDirectoryPathReplacementAndRemoval(t *testing.T) {
 dir := privateDir(t)
 f, err := os.Open(dir)
 if err != nil { t.Fatal(err) }
 defer f.Close()
 opened, err := f.Stat()
 if err != nil { t.Fatal(err) }
 moved := dir + ".moved"
 if err := os.Rename(dir, moved); err != nil { t.Fatal(err) }
 if err := verifyAuditDirectoryPath(dir, opened); err == nil || !strings.Contains(err.Error(), "disappeared") {
  t.Fatalf("detached directory accepted: %v", err)
 }
 if err := os.Mkdir(dir, 0700); err != nil { t.Fatal(err) }
 if err := verifyAuditDirectoryPath(dir, opened); err == nil || !strings.Contains(err.Error(), "replaced") {
  t.Fatalf("replacement directory accepted: %v", err)
 }
 if err := os.Remove(dir); err != nil { t.Fatal(err) }
 if err := os.Symlink(moved, dir); err != nil { t.Fatal(err) }
 if err := verifyAuditDirectoryPath(dir, opened); err == nil || !strings.Contains(err.Error(), "real directory") {
  t.Fatalf("symlink replacement accepted: %v", err)
 }
}

func TestVerifyAuditDirectoryPathPermissionDrift(t *testing.T) {
 dir := privateDir(t)
 f, err := os.Open(dir)
 if err != nil { t.Fatal(err) }
 defer f.Close()
 opened, err := f.Stat()
 if err != nil { t.Fatal(err) }
 if err := os.Chmod(dir, 0777); err != nil { t.Fatal(err) }
 if err := verifyAuditDirectoryPath(dir, opened); err == nil || !strings.Contains(err.Error(), "writable") {
  t.Fatalf("unsafe permissions accepted: %v", err)
 }
 if err := os.Chmod(dir, 0700); err != nil { t.Fatal(err) }
 if err := verifyAuditDirectoryPath(dir, opened); err != nil { t.Fatal(err) }
 // A sibling directory does not change the opened directory's identity.
 if err := os.Mkdir(filepath.Join(filepath.Dir(dir), "sibling"), 0700); err != nil { t.Fatal(err) }
 if err := verifyAuditDirectoryPath(dir, opened); err != nil { t.Fatal(err) }
}
