package backup

import (
    "os"
    "path/filepath"
    "strings"
    "testing"
)

func TestBackupRefusesDestinationThroughSymlinkedDataAlias(t *testing.T) {
    root := t.TempDir()
    source := filepath.Join(root, "data")
    if err := os.MkdirAll(filepath.Join(source, "delivery-queue"), 0700); err != nil { t.Fatal(err) }
    if err := os.WriteFile(filepath.Join(source, "config.json"), []byte("{}"), 0600); err != nil { t.Fatal(err) }
    for _, target := range []string{source, filepath.Join(source, "delivery-queue")} {
        alias := filepath.Join(root, "alias")
        if err := os.Symlink(target, alias); err != nil { t.Skip(err) }
        archive := filepath.Join(alias, "backup.zip")
        err := Create(source, archive)
        if err == nil || !strings.Contains(err.Error(), "resolves inside") {
            t.Fatalf("accepted backup inside source through symlink %q: %v", alias, err)
        }
        if _, err := os.Lstat(archive); !os.IsNotExist(err) {
            t.Fatalf("backup was created within source: %v", err)
        }
        if err := os.Remove(alias); err != nil { t.Fatal(err) }
    }
}

func TestBackupAcceptsDestinationOutsideSourceViaSymlink(t *testing.T) {
    root := t.TempDir()
    source := filepath.Join(root, "data")
    outside := filepath.Join(root, "outside")
    if err := os.Mkdir(source, 0700); err != nil { t.Fatal(err) }
    if err := os.Mkdir(outside, 0700); err != nil { t.Fatal(err) }
    if err := os.WriteFile(filepath.Join(source, "config.json"), []byte("{}"), 0600); err != nil { t.Fatal(err) }
    alias := filepath.Join(root, "external-alias")
    if err := os.Symlink(outside, alias); err != nil { t.Skip(err) }
    archive := filepath.Join(alias, "backup.zip")
    if err := Create(source, archive); err != nil { t.Fatal(err) }
    if _, err := Verify(archive); err != nil { t.Fatal(err) }
}
