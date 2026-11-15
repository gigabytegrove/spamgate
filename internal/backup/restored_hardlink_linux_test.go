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
