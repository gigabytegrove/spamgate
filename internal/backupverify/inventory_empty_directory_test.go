package backupverify

import (
 "os"
 "path/filepath"
 "testing"
)

func TestInventoryRejectsEmptyDirectories(t *testing.T) {
 root := t.TempDir()
 if err := os.MkdirAll(filepath.Join(root, "mail", "empty"), 0700); err != nil { t.Fatal(err) }
 if err := os.WriteFile(filepath.Join(root, "mail", "message"), []byte("body"), 0600); err != nil { t.Fatal(err) }
 if m, err := BuildInventory(root); err != nil || m.Version != 2 || len(m.Directories) != 2 {
  t.Fatalf("expected v2 directory preservation, manifest=%+v err=%v", m, err)
 }
}

func TestVerifyCompleteRejectsNewEmptyDirectory(t *testing.T) {
 root, _ := fixture(t)
 key := []byte("0123456789abcdef0123456789abcdef")
 signed, err := CreateSignedInventory(root, key)
 if err != nil { t.Fatal(err) }
 if err := os.Mkdir(filepath.Join(root, "unlisted-empty"), 0700); err != nil { t.Fatal(err) }
 if _, err := VerifyComplete(root, signed, key); err == nil {
  t.Fatal("unlisted empty directory silently accepted")
 }
}

func TestColdRestoreRefusesUnlistedDirectory(t *testing.T) {
 root, _ := fixture(t)
 key := []byte("0123456789abcdef0123456789abcdef")
 signed, err := CreateSignedInventory(root, key)
 if err != nil { t.Fatal(err) }
 if err := os.Mkdir(filepath.Join(root, "unlisted-empty"), 0700); err != nil { t.Fatal(err) }
 parent := t.TempDir()
 target := filepath.Join(parent, "restored")
 if _, err := RestoreCold(root, target, signed, key); err == nil { t.Fatal("restore accepted incomplete tree") }
 if _, err := os.Lstat(target); !os.IsNotExist(err) { t.Fatalf("unexpected target: %v", err) }
 entries, err := os.ReadDir(parent)
 if err != nil { t.Fatal(err) }
 if len(entries) != 0 { t.Fatalf("staging debris: %v", entries) }
}
