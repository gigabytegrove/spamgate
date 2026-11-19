//go:build linux

package backupverify

import (
 "os"
 "path/filepath"
 "strings"
 "testing"
)

func TestInventoryRejectsHardLinkedBackupFile(t *testing.T) {
 root, _ := fixture(t)
 source := filepath.Join(root, "db", "mail.db")
 alias := filepath.Join(root, "alias.db")
 if err := os.Link(source, alias); err != nil { t.Skipf("hard links unavailable: %v", err) }
 if _, err := BuildInventory(root); err == nil || !strings.Contains(err.Error(), "multiple hard links") {
  t.Fatalf("expected hard link refusal, got %v", err)
 }
}

func TestVerifyRejectsHardLinkedBackupFile(t *testing.T) {
 root, manifest := fixture(t)
 source := filepath.Join(root, "db", "mail.db")
 alias := filepath.Join(t.TempDir(), "external-alias.db")
 if err := os.Link(source, alias); err != nil { t.Skipf("hard links unavailable: %v", err) }
 if _, err := Verify(root, manifest); err == nil || !strings.Contains(err.Error(), "multiple hard links") {
  t.Fatalf("expected hard link refusal, got %v", err)
 }
}

func TestInventoryAllowsDistinctRegularFiles(t *testing.T) {
 root, _ := fixture(t)
 if err := os.WriteFile(filepath.Join(root, "other"), []byte("independent"), 0600); err != nil { t.Fatal(err) }
 manifest, err := BuildInventory(root)
 if err != nil { t.Fatal(err) }
 if len(manifest.Files) != 2 { t.Fatalf("expected 2 independent files, got %d", len(manifest.Files)) }
 if _, err := Verify(root, manifest); err != nil { t.Fatal(err) }
}
