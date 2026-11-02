package backup

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestBackupRefusesInitializedPolicyWithoutCounters(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "data")
	if err := os.MkdirAll(source, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "config.json"), []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, ".delivery-policy.initialized"), []byte("spamgate-delivery-policy-v1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(root, "refused.zip")
	if err := Create(source, archive); err == nil || !strings.Contains(err.Error(), "without its state") {
		t.Fatalf("incomplete policy snapshot accepted: %v", err)
	}
	if _, err := os.Stat(archive); !os.IsNotExist(err) {
		t.Fatalf("incomplete backup published: %v", err)
	}
}

func TestVerifyAndRestoreRefusePolicyMarkerOnlyArchive(t *testing.T) {
	root := t.TempDir()
	archive := filepath.Join(root, "forged.zip")
	f, err := os.Create(archive)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	contents := map[string]string{
		"config.json": "{}",
		".delivery-policy.initialized": "spamgate-delivery-policy-v1\n",
	}
	manifest := Manifest{Format: 1, Product: "SpamGate", Created: time.Now().UTC()}
	for name, body := range contents {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256([]byte(body))
		manifest.Entries = append(manifest.Entries, Entry{
			Path: name, Bytes: int64(len(body)), SHA256: hex.EncodeToString(digest[:]),
		})
	}
	w, err := zw.Create(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.NewEncoder(w).Encode(manifest); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(archive); err == nil || !strings.Contains(err.Error(), "without state") {
		t.Fatalf("incomplete archive passed verification: %v", err)
	}
	dest := filepath.Join(root, "restored")
	if err := Restore(archive, dest); err == nil || !strings.Contains(err.Error(), "without state") {
		t.Fatalf("incomplete archive restored: %v", err)
	}
	if _, err := os.Lstat(dest); !os.IsNotExist(err) {
		t.Fatalf("unsafe restore published directory: %v", err)
	}
}
