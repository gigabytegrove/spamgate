package backup

import (
 "os"
 "path/filepath"
 "strings"
 "testing"
)

func TestVerifyBackupCopiedFilesStable(t *testing.T) {
 root := t.TempDir()
 path := filepath.Join(root, "message.eml")
 if err := os.WriteFile(path, []byte("original"), 0600); err != nil { t.Fatal(err) }
 info, err := os.Lstat(path); if err != nil { t.Fatal(err) }
 if err := verifyBackupCopiedFiles(map[string]os.FileInfo{path:info}); err != nil { t.Fatal(err) }
}

func TestVerifyBackupCopiedFilesRejectsLateReplacement(t *testing.T) {
 root := t.TempDir()
 path := filepath.Join(root, "message.eml")
 if err := os.WriteFile(path, []byte("original"), 0600); err != nil { t.Fatal(err) }
 info, err := os.Lstat(path); if err != nil { t.Fatal(err) }
 if err := os.Rename(path, path+".old"); err != nil { t.Fatal(err) }
 if err := os.WriteFile(path, []byte("original"), 0600); err != nil { t.Fatal(err) }
 err = verifyBackupCopiedFiles(map[string]os.FileInfo{path:info})
 if err == nil || !strings.Contains(err.Error(), path) { t.Fatalf("late replacement accepted: %v", err) }
}

func TestVerifyBackupCopiedFilesRejectsLateRemoval(t *testing.T) {
 root := t.TempDir()
 path := filepath.Join(root, "message.eml")
 if err := os.WriteFile(path, []byte("original"), 0600); err != nil { t.Fatal(err) }
 info, err := os.Lstat(path); if err != nil { t.Fatal(err) }
 if err := os.Remove(path); err != nil { t.Fatal(err) }
 if err := verifyBackupCopiedFiles(map[string]os.FileInfo{path:info}); err == nil { t.Fatal("late removal accepted") }
}

func TestVerifyBackupCopiedFilesRejectsLateAppend(t *testing.T) {
 root := t.TempDir()
 path := filepath.Join(root, "message.eml")
 if err := os.WriteFile(path, []byte("original"), 0600); err != nil { t.Fatal(err) }
 info, err := os.Lstat(path); if err != nil { t.Fatal(err) }
 f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0); if err != nil { t.Fatal(err) }
 if _, err := f.Write([]byte("late")); err != nil { f.Close(); t.Fatal(err) }
 if err := f.Close(); err != nil { t.Fatal(err) }
 if err := verifyBackupCopiedFiles(map[string]os.FileInfo{path:info}); err == nil { t.Fatal("late append accepted") }
}
