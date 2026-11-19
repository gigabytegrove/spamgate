package backupverify

import (
 "os"
 "path/filepath"
 "testing"
)

func TestBuildInventoryAndVerifyComplete(t *testing.T) {
 root, _ := fixture(t)
 if err := os.WriteFile(filepath.Join(root, "extra.txt"), []byte("other"), 0600); err != nil { t.Fatal(err) }
 m, err := BuildInventory(root)
 if err != nil { t.Fatal(err) }
 if len(m.Files) != 2 || m.Files[0].Path != "db/mail.db" || m.Files[1].Path != "extra.txt" {
  t.Fatalf("unexpected inventory: %+v", m.Files)
 }
 key := []byte("0123456789abcdef0123456789abcdef")
 signed, err := SignManifest(m, key)
 if err != nil { t.Fatal(err) }
 report, err := VerifyComplete(root, signed, key)
 if err != nil || report.Files != 2 || report.Bytes != 12 { t.Fatalf("report=%+v err=%v", report, err) }
 if err := os.WriteFile(filepath.Join(root, "unexpected"), []byte("x"), 0600); err != nil { t.Fatal(err) }
 if _, err := VerifyComplete(root, signed, key); err == nil { t.Fatal("extra file accepted") }
 if err := os.Remove(filepath.Join(root, "unexpected")); err != nil { t.Fatal(err) }
 if err := os.Remove(filepath.Join(root, "extra.txt")); err != nil { t.Fatal(err) }
 if _, err := VerifyComplete(root, signed, key); err == nil { t.Fatal("missing file accepted") }
}

func TestBuildInventoryRefusesLinksAndSpecialFiles(t *testing.T) {
 root, _ := fixture(t)
 if err := os.Symlink("db/mail.db", filepath.Join(root, "linked")); err != nil { t.Skip(err) }
 if _, err := BuildInventory(root); err == nil { t.Fatal("symlink accepted") }
 if err := os.Remove(filepath.Join(root, "linked")); err != nil { t.Fatal(err) }
 if err := os.Symlink("db", filepath.Join(root, "linked-dir")); err != nil { t.Skip(err) }
 if _, err := BuildInventory(root); err == nil { t.Fatal("symlink directory accepted") }
}

func TestVerifyCompleteRejectsWrongKeyBeforeInventory(t *testing.T) {
 root, m := fixture(t)
 key := []byte("0123456789abcdef0123456789abcdef")
 signed, err := SignManifest(m, key)
 if err != nil { t.Fatal(err) }
 if _, err := VerifyComplete(root, signed, []byte("abcdef0123456789abcdef0123456789")); err == nil {
  t.Fatal("wrong key accepted")
 }
}

func TestBuildInventoryEmptyAndRootLink(t *testing.T) {
 empty := t.TempDir()
 if _, err := BuildInventory(empty); err == nil { t.Fatal("empty backup accepted") }
 parent := t.TempDir()
 link := filepath.Join(parent, "link")
 if err := os.Symlink(empty, link); err != nil { t.Skip(err) }
 if _, err := BuildInventory(link); err == nil { t.Fatal("symlink root accepted") }
}
