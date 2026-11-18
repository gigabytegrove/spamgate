package backup

import (
 "os"
 "path/filepath"
 "runtime"
 "strings"
 "testing"
)

// A source may be valid on Linux yet ambiguous on a recovery filesystem.
// Creation must reject it without publishing an archive.
func TestCreateRejectsCaseAmbiguousSourceWithoutPublishing(t *testing.T) {
 if runtime.GOOS != "linux" { t.Skip("requires case-sensitive Linux source") }
 root := t.TempDir()
 source := filepath.Join(root, "data")
 if err := os.Mkdir(source, 0700); err != nil { t.Fatal(err) }
 for _, name := range []string{"Mail.eml", "mail.eml"} {
  if err := os.WriteFile(filepath.Join(source,name), []byte("message"), 0600); err != nil { t.Fatal(err) }
 }
 archive := filepath.Join(root, "backup.zip")
 err := Create(source, archive)
 if err == nil { t.Fatal("ambiguous source accepted") }
 if !strings.Contains(err.Error(), "case-insensitive path collision") {
  t.Fatalf("expected explicit portable identity rejection, got %v", err)
 }
 if _, err := os.Lstat(archive); !os.IsNotExist(err) {
  t.Fatalf("backup unexpectedly published or unexpected stat error: %v", err)
 }
}

func TestCreateRejectsAncestorCaseCollisionWithoutPublishing(t *testing.T) {
 if runtime.GOOS != "linux" { t.Skip("requires case-sensitive Linux source") }
 root := t.TempDir()
 source := filepath.Join(root, "data")
 if err := os.MkdirAll(filepath.Join(source, "Mail"), 0700); err != nil { t.Fatal(err) }
 if err := os.WriteFile(filepath.Join(source, "Mail", "message.eml"), []byte("message"), 0600); err != nil { t.Fatal(err) }
 if err := os.WriteFile(filepath.Join(source, "mail"), []byte("file"), 0600); err != nil { t.Fatal(err) }
 archive := filepath.Join(root, "backup.zip")
 err := Create(source, archive)
 if err == nil || !strings.Contains(err.Error(), "file/directory collision") {
  t.Fatalf("expected case-insensitive ancestor collision, got %v", err)
 }
 if _, err := os.Lstat(archive); !os.IsNotExist(err) {
  t.Fatalf("backup unexpectedly published or unexpected stat error: %v", err)
 }
}
