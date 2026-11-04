package backup

import (
 "os"
 "path/filepath"
 "testing"
)

func TestVerifyBackupSourcePathDirectoryStable(t *testing.T) {
 root := t.TempDir()
 before, err := os.Lstat(root)
 if err != nil { t.Fatal(err) }
 if err := verifyBackupSourcePath(root, before); err != nil { t.Fatalf("stable directory rejected: %v", err) }
}

func TestVerifyBackupSourcePathDirectoryReplacement(t *testing.T) {
 parent := t.TempDir()
 root := filepath.Join(parent, "data")
 if err := os.Mkdir(root, 0700); err != nil { t.Fatal(err) }
 before, err := os.Lstat(root)
 if err != nil { t.Fatal(err) }
 moved := filepath.Join(parent, "old")
 if err := os.Rename(root, moved); err != nil { t.Fatal(err) }
 if err := os.Mkdir(root, 0700); err != nil { t.Fatal(err) }
 if err := verifyBackupSourcePath(root, before); err == nil { t.Fatal("replacement directory accepted") }
}

func TestVerifyBackupSourcePathDirectorySymlink(t *testing.T) {
 parent := t.TempDir()
 root := filepath.Join(parent, "data")
 if err := os.Mkdir(root, 0700); err != nil { t.Fatal(err) }
 before, err := os.Lstat(root)
 if err != nil { t.Fatal(err) }
 moved := filepath.Join(parent, "old")
 if err := os.Rename(root, moved); err != nil { t.Fatal(err) }
 if err := os.Symlink(moved, root); err != nil { t.Skipf("symlink unavailable: %v", err) }
 if err := verifyBackupSourcePath(root, before); err == nil { t.Fatal("symlink replacement accepted") }
}
