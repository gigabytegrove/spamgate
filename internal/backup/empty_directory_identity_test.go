package backup

import (
 "os"
 "path/filepath"
 "runtime"
 "strings"
 "testing"
)

func TestCreateRejectsEmptyDirectoryCaseCollision(t *testing.T) {
 if runtime.GOOS != "linux" { t.Skip("requires case-sensitive source filesystem") }
 root := t.TempDir()
 source := filepath.Join(root, "data")
 if err := os.MkdirAll(source, 0700); err != nil { t.Fatal(err) }
 for _, name := range []string{"Archive", "archive"} {
  if err := os.Mkdir(filepath.Join(source, name), 0700); err != nil { t.Skipf("case-sensitive filesystem required: %v", err) }
 }
 if err := os.WriteFile(filepath.Join(source, "valid.eml"), []byte("message"), 0600); err != nil { t.Fatal(err) }
 archive := filepath.Join(root, "backup.zip")
 err := Create(source, archive)
 if err == nil || !strings.Contains(err.Error(), "case-insensitive path collision") { t.Fatalf("expected directory collision refusal, got %v", err) }
 if _, err := os.Lstat(archive); !os.IsNotExist(err) { t.Fatalf("archive published despite collision: %v", err) }
}

func TestCreateRejectsCaseCollisionBetweenEmptyDirectoryAndFile(t *testing.T) {
 if runtime.GOOS != "linux" { t.Skip("requires case-sensitive source filesystem") }
 root := t.TempDir()
 source := filepath.Join(root, "data")
 if err := os.MkdirAll(filepath.Join(source, "Mail"), 0700); err != nil { t.Fatal(err) }
 if err := os.WriteFile(filepath.Join(source, "mail"), []byte("file"), 0600); err != nil { t.Skipf("case-sensitive filesystem required: %v", err) }
 archive := filepath.Join(root, "backup.zip")
 err := Create(source, archive)
 if err == nil || !strings.Contains(err.Error(), "case-insensitive path collision") { t.Fatalf("expected file/directory collision refusal, got %v", err) }
 if _, err := os.Lstat(archive); !os.IsNotExist(err) { t.Fatalf("archive published despite collision: %v", err) }
}

func TestCreateAllowsDistinctEmptyDirectories(t *testing.T) {
 root := t.TempDir()
 source := filepath.Join(root, "data")
 for _, name := range []string{"Archive", "Mailbox"} {
  if err := os.MkdirAll(filepath.Join(source, name), 0700); err != nil { t.Fatal(err) }
 }
 if err := os.WriteFile(filepath.Join(source, "valid.eml"), []byte("message"), 0600); err != nil { t.Fatal(err) }
 archive := filepath.Join(root, "backup.zip")
 if err := Create(source, archive); err != nil { t.Fatal(err) }
 if _, err := Verify(archive); err != nil { t.Fatal(err) }
}
