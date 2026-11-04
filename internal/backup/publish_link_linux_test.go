//go:build linux

package backup

import (
 "os"
 "path/filepath"
 "strings"
 "testing"
)

func TestPublishBackupLinkAnchoredToDirectory(t *testing.T) {
 root := t.TempDir()
 parent := filepath.Join(root, "out")
 if err := os.Mkdir(parent, 0700); err != nil { t.Fatal(err) }
 original, err := os.Lstat(parent)
 if err != nil { t.Fatal(err) }
 source := filepath.Join(parent, "temp.zip")
 if err := os.WriteFile(source, []byte("archive"), 0600); err != nil { t.Fatal(err) }
 dest := filepath.Join(parent, "backup.zip")
 if err := publishBackupLink(source, dest, original); err != nil { t.Fatal(err) }
 data, err := os.ReadFile(dest)
 if err != nil || string(data) != "archive" { t.Fatalf("published content: %q, %v", data, err) }
 if err := publishBackupLink(source, dest, original); err == nil || (!os.IsExist(err) && !strings.Contains(err.Error(), "file exists")) { t.Fatalf("overwrite must fail: %v", err) }
}

func TestPublishBackupLinkRejectsReplacedDirectory(t *testing.T) {
 root := t.TempDir()
 parent := filepath.Join(root, "out")
 if err := os.Mkdir(parent, 0700); err != nil { t.Fatal(err) }
 original, err := os.Lstat(parent)
 if err != nil { t.Fatal(err) }
 if err := os.Rename(parent, parent+"-old"); err != nil { t.Fatal(err) }
 if err := os.Mkdir(parent, 0700); err != nil { t.Fatal(err) }
 source := filepath.Join(parent, "temp.zip")
 if err := os.WriteFile(source, []byte("archive"), 0600); err != nil { t.Fatal(err) }
 if err := publishBackupLink(source, filepath.Join(parent, "backup.zip"), original); err == nil { t.Fatal("replaced directory accepted") }
 if _, err := os.Stat(filepath.Join(parent, "backup.zip")); !os.IsNotExist(err) { t.Fatalf("unexpected publication: %v", err) }
}

func TestPublishBackupLinkRejectsSymlinkParent(t *testing.T) {
 root := t.TempDir()
 parent := filepath.Join(root, "out")
 if err := os.Mkdir(parent, 0700); err != nil { t.Fatal(err) }
 original, err := os.Lstat(parent)
 if err != nil { t.Fatal(err) }
 if err := os.Rename(parent, parent+"-old"); err != nil { t.Fatal(err) }
 if err := os.Symlink(parent+"-old", parent); err != nil { t.Fatal(err) }
 if err := publishBackupLink(filepath.Join(parent,"temp.zip"),filepath.Join(parent,"backup.zip"),original); err == nil { t.Fatal("symlink parent accepted") }
}
