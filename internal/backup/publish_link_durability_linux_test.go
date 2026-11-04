//go:build linux

package backup

import (
 "errors"
 "os"
 "path/filepath"
 "testing"
)

// The published name must refer to the exact temporary inode, and a
// preexisting destination (including a dangling symlink) must never be
// replaced. The publication helper also fsyncs the anchored parent inode.
func TestPublishBackupLinkIdentityAndNoReplace(t *testing.T) {
 parent := filepath.Join(t.TempDir(), "out")
 if err := os.Mkdir(parent, 0700); err != nil { t.Fatal(err) }
 expected, err := os.Lstat(parent)
 if err != nil { t.Fatal(err) }
 source := filepath.Join(parent, "temp.zip")
 if err := os.WriteFile(source, []byte("backup bytes"), 0600); err != nil { t.Fatal(err) }
 before, err := os.Lstat(source)
 if err != nil { t.Fatal(err) }
 destination := filepath.Join(parent, "archive.zip")
 if err := publishBackupLink(source, destination, expected); err != nil { t.Fatal(err) }
 after, err := os.Lstat(destination)
 if err != nil { t.Fatal(err) }
 if !os.SameFile(before, after) { t.Fatal("published inode differs from temporary archive") }
 if err := os.Remove(source); err != nil { t.Fatal(err) }
 if got, err := os.ReadFile(destination); err != nil || string(got) != "backup bytes" {
  t.Fatalf("published archive missing after temporary unlink: %q, %v", got, err)
 }
 if err := os.WriteFile(source, []byte("different"), 0600); err != nil { t.Fatal(err) }
 if err := publishBackupLink(source, destination, expected); !errors.Is(err, os.ErrExist) {
  t.Fatalf("existing archive must not be replaced: %v", err)
 }
 if err := os.Remove(destination); err != nil { t.Fatal(err) }
 if err := os.Symlink("missing-target", destination); err != nil { t.Fatal(err) }
 if err := publishBackupLink(source, destination, expected); !errors.Is(err, os.ErrExist) {
  t.Fatalf("dangling symlink destination must not be replaced: %v", err)
 }
 info, err := os.Lstat(destination)
 if err != nil || info.Mode()&os.ModeSymlink == 0 { t.Fatalf("destination symlink was replaced: %v, %v", info, err) }
}
