//go:build linux

package main

import (
 "os"
 "path/filepath"
 "strings"
 "testing"
)

func TestHistoryWriterExclusiveUntilReleased(t *testing.T) {
 dir := t.TempDir()
 release, err := acquireInstanceLock(dir)
 if err != nil { t.Fatal(err) }
 if _, err := acquireInstanceLock(dir); err == nil || !strings.Contains(err.Error(), "another SpamGate worker") {
  t.Fatalf("second writer must be refused, got %v", err)
 }
 if _, err := os.Stat(filepath.Join(dir, ".worker.lock")); err != nil { t.Fatal(err) }
 release()
 again, err := acquireInstanceLock(dir)
 if err != nil { t.Fatalf("lock not released after process exit: %v", err) }
 again()
}

func TestHistoryWriterRejectsSymlinkAndNonRegularLock(t *testing.T) {
 dir := t.TempDir()
 target := filepath.Join(dir, "target")
 if err := os.WriteFile(target, []byte("untouched"), 0600); err != nil {t.Fatal(err)}
 lock := filepath.Join(dir, ".worker.lock")
 if err := os.Symlink(target, lock); err != nil {t.Fatal(err)}
 if _, err := acquireInstanceLock(dir); err == nil {t.Fatal("symlink lock accepted")}
 b, err := os.ReadFile(target)
 if err != nil || string(b)!="untouched" {t.Fatal("symlink target touched")}
 if err := os.Remove(lock); err != nil {t.Fatal(err)}
 if err := os.Mkdir(lock, 0700); err != nil {t.Fatal(err)}
 if _, err := acquireInstanceLock(dir); err == nil {t.Fatal("directory lock accepted")}
}
