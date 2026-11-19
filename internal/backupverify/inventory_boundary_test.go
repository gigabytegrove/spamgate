package backupverify

import (
 "os"
 "path/filepath"
 "testing"
)

func TestSignedInventoryEntrypoint(t *testing.T) {
 root, _ := fixture(t)
 key := []byte("0123456789abcdef0123456789abcdef")
 signed, err := CreateSignedInventory(root, key)
 if err != nil { t.Fatal(err) }
 report, err := VerifyComplete(root, signed, key)
 if err != nil || report.Files != 1 { t.Fatalf("%+v %v", report, err) }
 if _, err := CreateSignedInventory(root, []byte("short")); err == nil { t.Fatal("weak key accepted") }
}

func TestCheckBackupBoundary(t *testing.T) {
 base := t.TempDir()
 active := filepath.Join(base, "data")
 backup := filepath.Join(base, "backup")
 for _, p := range []string{active, backup} {
  if err := os.Mkdir(p, 0700); err != nil { t.Fatal(err) }
 }
 if err := CheckBackupBoundary(active, backup); err != nil { t.Fatal(err) }
 if err := CheckBackupBoundary(active, active); err == nil { t.Fatal("active root accepted") }
 nested := filepath.Join(active, "backup")
 if err := os.Mkdir(nested, 0700); err != nil { t.Fatal(err) }
 if err := CheckBackupBoundary(active, nested); err == nil { t.Fatal("nested backup accepted") }
 if err := CheckBackupBoundary(nested, active); err == nil { t.Fatal("nested active accepted") }
 alias := filepath.Join(base, "alias")
 if err := os.Symlink(active, alias); err != nil { t.Skip(err) }
 if err := CheckBackupBoundary(active, alias); err == nil { t.Fatal("symlink alias accepted") }
 sibling := filepath.Join(base, "data2")
 if err := os.Mkdir(sibling, 0700); err != nil { t.Fatal(err) }
 if err := CheckBackupBoundary(active, sibling); err != nil { t.Fatalf("sibling rejected: %v", err) }
}
