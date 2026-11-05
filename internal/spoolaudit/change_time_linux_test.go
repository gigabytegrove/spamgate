//go:build linux

package spoolaudit

import (
 "os"
 "path/filepath"
 "testing"
 "time"
)

func TestAuditChangeTimeRejectsRestoredMtimeAfterSameSizeRewrite(t *testing.T) {
 dir := t.TempDir()
 path := filepath.Join(dir, "record")
 if err := os.WriteFile(path, []byte("AAAA"), 0600); err != nil { t.Fatal(err) }
 before, err := os.Lstat(path)
 if err != nil { t.Fatal(err) }
 // Ensure distinct ctime even on coarse-grained test filesystems.
 time.Sleep(15 * time.Millisecond)
 if err := os.WriteFile(path, []byte("BBBB"), 0600); err != nil { t.Fatal(err) }
 if err := os.Chtimes(path, before.ModTime(), before.ModTime()); err != nil { t.Fatal(err) }
 after, err := os.Lstat(path)
 if err != nil { t.Fatal(err) }
 if !os.SameFile(before, after) || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
  t.Fatal("test did not preserve inode, length and mtime")
 }
 if sameAuditChangeTime(before, after) { t.Fatal("in-place rewrite with restored mtime escaped Linux ctime check") }
 if err := verifyRecordPathStable(path, before); err == nil {
  t.Fatal("path stability accepted a rewritten original")
 }
}

func TestAuditChangeTimeStableAndPermissionDrift(t *testing.T) {
 dir := t.TempDir()
 path := filepath.Join(dir, "record")
 if err := os.WriteFile(path, []byte("AAAA"), 0600); err != nil { t.Fatal(err) }
 before, err := os.Lstat(path)
 if err != nil { t.Fatal(err) }
 stable, err := os.Lstat(path)
 if err != nil { t.Fatal(err) }
 if !sameAuditChangeTime(before, stable) { t.Fatal("stable original rejected") }
 time.Sleep(15 * time.Millisecond)
 if err := os.Chmod(path, 0640); err != nil { t.Fatal(err) }
 changed, err := os.Lstat(path)
 if err != nil { t.Fatal(err) }
 if sameAuditChangeTime(before, changed) { t.Fatal("permission drift escaped ctime check") }
}
