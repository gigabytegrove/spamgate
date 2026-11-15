//go:build linux

package backup

import (
 "os"
 "path/filepath"
 "strings"
 "testing"
)

func TestVerifyRestoredRejectsHardlinkOutsideDestination(t *testing.T) {
 archive, dest := restoredFixture(t)
 original := filepath.Join(dest, "events.jsonl")
 outside := filepath.Join(filepath.Dir(dest), "outside-events.jsonl")
 if err := os.Link(original, outside); err != nil { t.Skipf("hard links unsupported: %v", err) }
 _, err := VerifyRestored(archive, dest)
 if err == nil || !strings.Contains(err.Error(), "hard-linked file") {
  t.Fatalf("expected hard-link refusal, got %v", err)
 }
}

func TestVerifyRestoredRejectsHardlinkedRuntimeLock(t *testing.T) {
 archive, dest := restoredFixture(t)
 lock := filepath.Join(dest, ".events-journal.lock")
 if err := os.WriteFile(lock, nil, 0600); err != nil { t.Fatal(err) }
 outside := filepath.Join(filepath.Dir(dest), "outside-lock")
 if err := os.Link(lock, outside); err != nil { t.Skipf("hard links unsupported: %v", err) }
 _, err := VerifyRestored(archive, dest)
 if err == nil || !strings.Contains(err.Error(), "hard-linked file") {
  t.Fatalf("expected hard-linked lock refusal, got %v", err)
 }
}

func TestVerifyRestoredAcceptsSingleLinkFiles(t *testing.T) {
 archive, dest := restoredFixture(t)
 if _, err := VerifyRestored(archive, dest); err != nil {
  t.Fatalf("ordinary restored files rejected: %v", err)
 }
}

func TestOpenedDescriptorDetectsHardlinkAddedAfterInitialStat(t *testing.T) {
 dir := t.TempDir()
 path := filepath.Join(dir, "message")
 if err := os.WriteFile(path, []byte("payload"), 0600); err != nil { t.Fatal(err) }
 before, err := os.Lstat(path)
 if err != nil { t.Fatal(err) }
 if err := rejectRestoredHardlink(before, "message"); err != nil { t.Fatal(err) }
 f, err := os.Open(path)
 if err != nil { t.Fatal(err) }
 defer f.Close()
 alias := filepath.Join(dir, "alias")
 if err := os.Link(path, alias); err != nil { t.Skipf("hard links unsupported: %v", err) }
 opened, err := f.Stat()
 if err != nil { t.Fatal(err) }
 if err := rejectRestoredHardlink(opened, "message"); err == nil || !strings.Contains(err.Error(), "hard-linked file") {
  t.Fatalf("opened descriptor must reject newly linked inode, got %v", err)
 }
}

func TestOpenedDescriptorDetectsHardlinkAfterRead(t *testing.T) {
 dir := t.TempDir()
 path := filepath.Join(dir, "message")
 if err := os.WriteFile(path, []byte("payload"), 0600); err != nil { t.Fatal(err) }
 f, err := os.Open(path)
 if err != nil { t.Fatal(err) }
 defer f.Close()
 opened, err := f.Stat()
 if err != nil { t.Fatal(err) }
 if err := rejectRestoredHardlink(opened, "message"); err != nil { t.Fatal(err) }
 alias := filepath.Join(dir, "alias")
 if err := os.Link(path, alias); err != nil { t.Skipf("hard links unsupported: %v", err) }
 finished, err := f.Stat()
 if err != nil { t.Fatal(err) }
 if err := rejectRestoredHardlink(finished, "message"); err == nil || !strings.Contains(err.Error(), "hard-linked file") {
  t.Fatalf("completed descriptor must reject newly linked inode, got %v", err)
 }
}
