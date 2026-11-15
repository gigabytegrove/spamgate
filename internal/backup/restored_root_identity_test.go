package backup

import (
    "os"
    "path/filepath"
    "testing"
)

func TestVerifyRestoredRootIdentityStable(t *testing.T) {
    root := filepath.Join(t.TempDir(), "data")
    if err := os.Mkdir(root, 0700); err != nil { t.Fatal(err) }
    before, err := os.Lstat(root)
    if err != nil { t.Fatal(err) }
    if err := verifyRestoredRootIdentity(root, before); err != nil { t.Fatal(err) }
}

func TestVerifyRestoredRootIdentityRejectsReplacement(t *testing.T) {
    parent := t.TempDir()
    root := filepath.Join(parent, "data")
    if err := os.Mkdir(root, 0700); err != nil { t.Fatal(err) }
    before, err := os.Lstat(root)
    if err != nil { t.Fatal(err) }
    if err := os.Rename(root, filepath.Join(parent, "old")); err != nil { t.Fatal(err) }
    if err := os.Mkdir(root, 0700); err != nil { t.Fatal(err) }
    if err := verifyRestoredRootIdentity(root, before); err == nil { t.Fatal("replacement directory accepted") }
}

func TestVerifyRestoredRootIdentityRejectsSymlinkAndMissingRoot(t *testing.T) {
    parent := t.TempDir()
    root := filepath.Join(parent, "data")
    if err := os.Mkdir(root, 0700); err != nil { t.Fatal(err) }
    before, err := os.Lstat(root)
    if err != nil { t.Fatal(err) }
    moved := filepath.Join(parent, "moved")
    if err := os.Rename(root, moved); err != nil { t.Fatal(err) }
    if err := verifyRestoredRootIdentity(root, before); err == nil { t.Fatal("missing root accepted") }
    if err := os.Symlink(moved, root); err != nil { t.Fatal(err) }
    if err := verifyRestoredRootIdentity(root, before); err == nil { t.Fatal("symlink replacement accepted") }
}
