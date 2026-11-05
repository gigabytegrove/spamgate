package backup

import (
 "os"
 "path/filepath"
 "testing"
)

func TestVerifyBackupDestinationParent(t *testing.T) {
 root := t.TempDir()
 parent := filepath.Join(root, "out")
 if err := os.Mkdir(parent, 0700); err != nil { t.Fatal(err) }
 original, err := os.Lstat(parent)
 if err != nil { t.Fatal(err) }
 resolved, err := filepath.EvalSymlinks(parent)
 if err != nil { t.Fatal(err) }
 if err := verifyBackupDestinationParent(parent, resolved, original); err != nil { t.Fatalf("stable parent rejected: %v", err) }
 moved := filepath.Join(root, "old")
 if err := os.Rename(parent, moved); err != nil { t.Fatal(err) }
 if err := os.Mkdir(parent, 0700); err != nil { t.Fatal(err) }
 if err := verifyBackupDestinationParent(parent, resolved, original); err == nil { t.Fatal("replaced parent accepted") }
}

func TestVerifyBackupDestinationParentSymlinkSwap(t *testing.T) {
 root := t.TempDir()
 realParent := filepath.Join(root, "outside")
 data := filepath.Join(root, "data")
 if err := os.Mkdir(realParent, 0700); err != nil { t.Fatal(err) }
 if err := os.Mkdir(data, 0700); err != nil { t.Fatal(err) }
 link := filepath.Join(root, "destination")
 if err := os.Symlink(realParent, link); err != nil { t.Skipf("symlink unavailable: %v", err) }
 original, err := os.Stat(link)
 if err != nil { t.Fatal(err) }
 resolved, err := filepath.EvalSymlinks(link)
 if err != nil { t.Fatal(err) }
 if err := verifyBackupDestinationParent(link, resolved, original); err != nil { t.Fatalf("stable symlink rejected: %v", err) }
 if err := os.Remove(link); err != nil { t.Fatal(err) }
 if err := os.Symlink(data, link); err != nil { t.Fatal(err) }
 if err := verifyBackupDestinationParent(link, resolved, original); err == nil { t.Fatal("redirected symlink accepted") }
}
