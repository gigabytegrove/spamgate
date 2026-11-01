//go:build linux

package backup

import (
 "os"
 "path/filepath"
 "strings"
 "testing"
)

func TestVerifyRestoredRefusesBusyWorkerLock(t *testing.T) {
 archive, dest := restoredFixture(t)
 release, err := acquireOfflineLock(dest)
 if err != nil { t.Fatal(err) }
 defer release()
 if _, err := VerifyRestored(archive, dest); err == nil || !strings.Contains(err.Error(), "busy") {
  t.Fatalf("accepted active worker lock: %v", err)
 }
}

func TestRestoreReadLockDetectsNewOrReplacedInode(t *testing.T) {
 root := t.TempDir()
 release, check, err := acquireRestoreReadLock(root)
 if err != nil { t.Fatal(err) }
 defer release()
 if err := check(); err != nil { t.Fatal(err) }
 lock := filepath.Join(root, ".worker.lock")
 if err := os.WriteFile(lock, nil, 0600); err != nil { t.Fatal(err) }
 if err := check(); err == nil || !strings.Contains(err.Error(), "appeared") { t.Fatalf("missed newly created lock: %v", err) }
 release2, check2, err := acquireRestoreReadLock(root)
 if err != nil { t.Fatal(err) }
 defer release2()
 if err := os.Remove(lock); err != nil { t.Fatal(err) }
 if err := os.WriteFile(lock, nil, 0600); err != nil { t.Fatal(err) }
 if err := check2(); err == nil || !strings.Contains(err.Error(), "changed") { t.Fatalf("missed replaced lock: %v", err) }
}
