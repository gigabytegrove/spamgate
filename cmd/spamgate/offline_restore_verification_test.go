package main

import (
 "os"
 "path/filepath"
 "strings"
 "testing"

 "github.com/gigabytegrove/spamgate/internal/backup"
)

func TestOfflineRestoreVerificationCLI(t *testing.T) {
 root := t.TempDir()
 source := filepath.Join(root, "source")
 if err := os.Mkdir(source, 0700); err != nil { t.Fatal(err) }
 if err := os.WriteFile(filepath.Join(source, "config.json"), []byte("{\"setup_complete\":true}"), 0600); err != nil { t.Fatal(err) }
 archive := filepath.Join(root, "backup.zip")
 if err := backup.Create(source, archive); err != nil { t.Fatal(err) }
 dest := filepath.Join(root, "restored")
 if err := execute([]string{"-restore-backup", archive, "-data", dest}); err != nil { t.Fatal(err) }
 if err := execute([]string{"-verify-restored", archive, "-data", dest}); err != nil {
  t.Fatalf("valid restored data refused: %v", err)
 }
 if err := os.WriteFile(filepath.Join(dest, "config.json"), []byte("{\"setup_complete\":null}"), 0600); err != nil { t.Fatal(err) }
 if err := execute([]string{"-verify-restored", archive, "-data", dest}); err == nil || !strings.Contains(err.Error(), "SHA-256") {
  t.Fatalf("tampered restored data accepted: %v", err)
 }
}

func TestOfflineRestoreVerificationCLIRejectsConflictingModes(t *testing.T) {
 for _, flags := range [][]string{
  {"-backup-file", "a.zip", "-verify-restored", "b.zip"},
  {"-verify-backup", "a.zip", "-verify-restored", "b.zip"},
  {"-restore-backup", "a.zip", "-verify-restored", "b.zip"},
 } {
  if err := execute(flags); err == nil || !strings.Contains(err.Error(), "choose only one") {
   t.Fatalf("accepted conflicting offline operations %v: %v", flags, err)
  }
 }
}
