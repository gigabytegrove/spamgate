//go:build linux

package backup

import (
 "os"
 "path/filepath"
 "testing"
)

func TestOpenRestoredRegularNoFollowRejectsSymlink(t *testing.T) {
 dir := t.TempDir()
 target := filepath.Join(dir, "target")
 link := filepath.Join(dir, "link")
 if err := os.WriteFile(target, []byte("payload"), 0600); err != nil { t.Fatal(err) }
 if err := os.Symlink(target, link); err != nil { t.Fatal(err) }
 if f, err := openRestoredRegularNoFollow(link); err == nil {
  f.Close()
  t.Fatal("opened a symlink")
 }
 f, err := openRestoredRegularNoFollow(target)
 if err != nil { t.Fatal(err) }
 if err := f.Close(); err != nil { t.Fatal(err) }
}

func TestVerifyRestoredRejectsSymlinkedRuntimeLock(t *testing.T) {
 archive, dest := restoredFixture(t)
 outside := filepath.Join(t.TempDir(), "outside-lock")
 if err := os.WriteFile(outside, nil, 0600); err != nil { t.Fatal(err) }
 if err := os.Symlink(outside, filepath.Join(dest, ".events-journal.lock")); err != nil { t.Fatal(err) }
 if _, err := VerifyRestored(archive, dest); err == nil {
  t.Fatal("symlinked runtime lock accepted")
 }
}

func TestVerifyRestoredRejectsSymlinkedManifestFile(t *testing.T) {
 archive, dest := restoredFixture(t)
 path := filepath.Join(dest, "events.jsonl")
 outside := filepath.Join(t.TempDir(), "outside-events")
 content, err := os.ReadFile(path)
 if err != nil { t.Fatal(err) }
 if err := os.WriteFile(outside, content, 0600); err != nil { t.Fatal(err) }
 if err := os.Remove(path); err != nil { t.Fatal(err) }
 if err := os.Symlink(outside, path); err != nil { t.Fatal(err) }
 if _, err := VerifyRestored(archive, dest); err == nil {
  t.Fatal("symlinked manifest file accepted")
 }
}
