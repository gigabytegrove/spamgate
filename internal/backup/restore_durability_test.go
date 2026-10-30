package backup

import (
    "os"
    "path/filepath"
    "runtime"
    "testing"
)

func TestSyncRestoredTreeNestedDirectories(t *testing.T) {
    root := t.TempDir()
    stage := filepath.Join(root, "stage")
    nested := filepath.Join(stage, "mail", "spool", "queued")
    if err := os.MkdirAll(nested, 0700); err != nil { t.Fatal(err) }
    if err := os.WriteFile(filepath.Join(nested, "message.eml"), []byte("Subject: test\r\n\r\nbody"), 0600); err != nil { t.Fatal(err) }
    if err := syncRestoredTree(stage); err != nil { t.Fatal(err) }
    if err := publishRestoredDirectory(stage, filepath.Join(root, "published")); err != nil { t.Fatal(err) }
    if b, err := os.ReadFile(filepath.Join(root, "published", "mail", "spool", "queued", "message.eml")); err != nil || len(b) == 0 {
        t.Fatalf("published nested restore lost file: %q, %v", b, err)
    }
}

func TestSyncRestoredTreeRejectsSymlink(t *testing.T) {
    if runtime.GOOS != "linux" { t.Skip("Linux directory durability check") }
    stage := filepath.Join(t.TempDir(), "stage")
    if err := os.Mkdir(stage, 0700); err != nil { t.Fatal(err) }
    if err := os.Symlink("/etc", filepath.Join(stage, "escape")); err != nil { t.Skip(err) }
    if err := syncRestoredTree(stage); err == nil {
        t.Fatal("accepted symlink in restore staging tree")
    }
}
