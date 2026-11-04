package backup

import (
 "os"
 "path/filepath"
 "strings"
 "testing"
)

func TestBackupDirectorySnapshotsRejectNestedChanges(t *testing.T) {
 root := t.TempDir()
 nested := filepath.Join(root, "nested")
 if err := os.Mkdir(nested, 0700); err != nil { t.Fatal(err) }
 nestedInfo, err := os.Lstat(nested); if err != nil { t.Fatal(err) }
 snapshots := map[string]os.FileInfo{nested:nestedInfo}
 if err := verifyBackupDirectories(snapshots); err != nil { t.Fatalf("stable tree rejected: %v", err) }
 // Replace a visited nested directory without modifying the root pathname.
 moved := filepath.Join(root, "previous")
 if err := os.Rename(nested, moved); err != nil { t.Fatal(err) }
 if err := os.Mkdir(nested, 0700); err != nil { t.Fatal(err) }
 if err := verifyBackupDirectories(snapshots); err == nil || !strings.Contains(err.Error(), nested) {
  t.Fatalf("nested replacement not detected: %v", err)
 }
}

func TestBackupDirectorySnapshotsRejectNestedInsert(t *testing.T) {
 root := t.TempDir()
 nested := filepath.Join(root, "nested")
 if err := os.Mkdir(nested, 0700); err != nil { t.Fatal(err) }
 before, err := os.Lstat(nested); if err != nil { t.Fatal(err) }
 if err := os.WriteFile(filepath.Join(nested, "late-message.eml"), []byte("late"), 0600); err != nil { t.Fatal(err) }
 if err := verifyBackupDirectories(map[string]os.FileInfo{nested:before}); err == nil {
  t.Fatal("nested insertion after traversal accepted")
 }
}

func TestBackupRejectsReservedManifestSourceFile(t *testing.T) {
 root := t.TempDir()
 data := filepath.Join(root, "data")
 if err := os.Mkdir(data, 0700); err != nil { t.Fatal(err) }
 if err := os.WriteFile(filepath.Join(data, "config.json"), []byte("{}"), 0600); err != nil { t.Fatal(err) }
 if err := os.WriteFile(filepath.Join(data, manifestPath), []byte("forged"), 0600); err != nil { t.Fatal(err) }
 output := filepath.Join(root, "backup.zip")
 err := Create(data, output)
 if err == nil || !strings.Contains(err.Error(), "reserved") { t.Fatalf("reserved source accepted: %v", err) }
 if _, err := os.Lstat(output); !os.IsNotExist(err) { t.Fatalf("partial archive published: %v", err) }
}
