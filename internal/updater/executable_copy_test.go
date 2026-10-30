package updater

import (
 "crypto/sha256"
 "encoding/hex"
 "errors"
 "os"
 "path/filepath"
 "strings"
 "testing"
)

func TestPromotionRejectsSubstitutedStagedBytes(t *testing.T) {
 data := t.TempDir()
 stageTestBinary(t, data)
 staged, _, digest, err := pendingDetails(data)
 if err != nil { t.Fatal(err) }
 original, err := os.ReadFile(staged)
 if err != nil { t.Fatal(err) }
 original[200] ^= 1 // same length, different digest after Pending
 if err := os.WriteFile(staged, original, 0700); err != nil { t.Fatal(err) }
 target := runningPath(data)
 if err := copyExecutableVerified(staged, target, digest); err == nil || !strings.Contains(err.Error(), "checksum") {
  t.Fatalf("substituted staged executable accepted: %v", err)
 }
 if _, err := os.Lstat(target); !errors.Is(err, os.ErrNotExist) {
  t.Fatalf("unverified executable published: %v", err)
 }
 entries, err := os.ReadDir(updateDir(data))
 if err != nil { t.Fatal(err) }
 for _, e := range entries {
  if strings.HasPrefix(e.Name(), ".spamgate-exe-") { t.Fatalf("orphaned temporary executable: %s", e.Name()) }
 }
}

func TestExecutableCopyRejectsSourceAndParentSymlinks(t *testing.T) {
 root := t.TempDir()
 source := filepath.Join(root, "source")
 if err := os.WriteFile(source, []byte(strings.Repeat("source", 1024)), 0700); err != nil { t.Fatal(err) }
 link := filepath.Join(root, "link")
 if err := os.Symlink(source, link); err != nil { t.Skip(err) }
 target := filepath.Join(root, "target")
 if err := copyExecutable(link, target); err == nil { t.Fatal("followed source symlink") }
 if _, err := os.Lstat(target); !errors.Is(err, os.ErrNotExist) { t.Fatalf("created target: %v", err) }
 outside := t.TempDir()
 parent := filepath.Join(root, "parent-link")
 if err := os.Symlink(outside, parent); err != nil { t.Skip(err) }
 if err := copyExecutable(source, filepath.Join(parent, "target")); err == nil { t.Fatal("followed parent symlink") }
 if _, err := os.Stat(filepath.Join(outside, "target")); !errors.Is(err, os.ErrNotExist) {
  t.Fatalf("modified outside path: %v", err)
 }
}

func TestExecutableCopyDigestAndAtomicReplacement(t *testing.T) {
 root := t.TempDir()
 source := filepath.Join(root, "source")
 payload := []byte(strings.Repeat("staged-content", 512))
 if err := os.WriteFile(source, payload, 0700); err != nil { t.Fatal(err) }
 sum := sha256.Sum256(payload)
 digest := hex.EncodeToString(sum[:])
 target := filepath.Join(root, "active")
 if err := os.WriteFile(target, []byte("previous"), 0700); err != nil { t.Fatal(err) }
 if err := copyExecutableVerified(source, target, strings.Repeat("0", 64)); err == nil { t.Fatal("bad digest accepted") }
 old, err := os.ReadFile(target)
 if err != nil || string(old) != "previous" { t.Fatalf("invalid copy replaced active: %q %v", old, err) }
 if err := copyExecutableVerified(source, target, digest); err != nil { t.Fatal(err) }
 got, err := os.ReadFile(target)
 if err != nil || string(got) != string(payload) { t.Fatalf("wrong installed bytes: %v", err) }
 if err := copyExecutable(target, source); err != nil { t.Fatalf("rollback copy failed: %v", err) }
}

func TestExecutableCopyDoesNotOverwriteSymlinkTarget(t *testing.T) {
 root := t.TempDir()
 source := filepath.Join(root, "source")
 victim := filepath.Join(root, "config.json")
 target := filepath.Join(root, "active")
 if err := os.WriteFile(source, []byte(strings.Repeat("worker", 1024)), 0700); err != nil { t.Fatal(err) }
 if err := os.WriteFile(victim, []byte("keep-config"), 0600); err != nil { t.Fatal(err) }
 if err := os.Symlink(victim, target); err != nil { t.Skip(err) }
 if err := copyExecutable(source, target); err != nil { t.Fatal(err) }
 b, err := os.ReadFile(victim)
 if err != nil || string(b) != "keep-config" { t.Fatalf("overwrote symlink target: %q %v", b, err) }
 info, err := os.Lstat(target)
 if err != nil || !info.Mode().IsRegular() { t.Fatalf("active not regular: %v %v", info, err) }
}

func TestExecutableCopyRejectsWritableDestination(t *testing.T) {
 root := t.TempDir()
 source := filepath.Join(root, "source")
 if err := os.WriteFile(source, []byte("source"), 0700); err != nil { t.Fatal(err) }
 dir := filepath.Join(root, "unsafe")
 if err := os.Mkdir(dir, 0700); err != nil { t.Fatal(err) }
 if err := os.Chmod(dir, 0777); err != nil { t.Fatal(err) }
 if err := copyExecutable(source, filepath.Join(dir, "active")); err == nil { t.Fatal("accepted writable destination directory") }
}
