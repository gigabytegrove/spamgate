package backup

import (
 "os"
 "path/filepath"
 "testing"
)

// This exercises the on-disk readback gate through the public backup API,
// rather than only calling the ZIP manifest inspector directly.
func TestCreatePublishesReadableVerifiedArchive(t *testing.T) {
 root := t.TempDir()
 source := filepath.Join(root, "data")
 if err := os.Mkdir(source, 0700); err != nil { t.Fatal(err) }
 if err := os.WriteFile(filepath.Join(source, "message.eml"), []byte("Subject: test\r\n\r\nhello\r\n"), 0600); err != nil { t.Fatal(err) }
 archive := filepath.Join(root, "backup.zip")
 if err := Create(source, archive); err != nil { t.Fatalf("create and readback: %v", err) }
 manifest, err := Verify(archive)
 if err != nil { t.Fatalf("published archive is unreadable: %v", err) }
 if len(manifest.Entries) != 1 || manifest.Entries[0].Path != "message.eml" {
  t.Fatalf("unexpected published manifest: %+v", manifest.Entries)
 }
 if err := Create(source, archive); err == nil { t.Fatal("existing archive was overwritten") }
}

func TestCreateDoesNotPublishInvalidSource(t *testing.T) {
 root := t.TempDir()
 source := filepath.Join(root, "data")
 if err := os.Mkdir(source, 0700); err != nil { t.Fatal(err) }
 if err := os.WriteFile(filepath.Join(source, manifestPath), []byte("reserved"), 0600); err != nil { t.Fatal(err) }
 archive := filepath.Join(root, "backup.zip")
 if err := Create(source, archive); err == nil { t.Fatal("reserved manifest collision accepted") }
 if _, err := os.Lstat(archive); !os.IsNotExist(err) { t.Fatalf("failed backup published archive: %v", err) }
}
