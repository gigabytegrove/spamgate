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

func TestColdBackupRefusesInvalidPolicyMarkerEvidence(t *testing.T) {
	cases := []struct {
		name string
		body string
		mode os.FileMode
	}{
		{"wrong-version", "spamgate-delivery-policy-v2\n", 0600},
		{"truncated", "spamgate-delivery-policy-v1", 0600},
		{"extra-data", "spamgate-delivery-policy-v1\nextra", 0600},
		{"world-readable", backupPolicyMarkerText, 0644},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			source := filepath.Join(root, "data")
			if err := os.Mkdir(source, 0700); err != nil { t.Fatal(err) }
			if err := os.WriteFile(filepath.Join(source, "config.json"), []byte("{}"), 0600); err != nil { t.Fatal(err) }
			if err := os.WriteFile(filepath.Join(source, "delivery-policy.json"), []byte(`{"initialized":true,"greylist":{},"rates":{}}`), 0600); err != nil { t.Fatal(err) }
			marker := filepath.Join(source, backupPolicyMarkerPath)
			if err := os.WriteFile(marker, []byte(tc.body), tc.mode); err != nil { t.Fatal(err) }
			archive := filepath.Join(root, "backup.zip")
			if err := Create(source, archive); err == nil || !strings.Contains(err.Error(), "marker") {
				t.Fatalf("invalid marker accepted: %v", err)
			}
			if _, err := os.Lstat(archive); !os.IsNotExist(err) {
				t.Fatalf("invalid backup was published: %v", err)
			}
			body, err := os.ReadFile(marker)
			if err != nil || string(body) != tc.body { t.Fatal("forensic marker was changed") }
		})
	}
}

func TestColdBackupRefusesSymlinkedPolicyMarker(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "data")
	if err := os.Mkdir(source, 0700); err != nil { t.Fatal(err) }
	if err := os.WriteFile(filepath.Join(source, "config.json"), []byte("{}"), 0600); err != nil { t.Fatal(err) }
	if err := os.WriteFile(filepath.Join(source, "delivery-policy.json"), []byte(`{"initialized":true,"greylist":{},"rates":{}}`), 0600); err != nil { t.Fatal(err) }
	target := filepath.Join(root, "external-marker")
	if err := os.WriteFile(target, []byte(backupPolicyMarkerText), 0600); err != nil { t.Fatal(err) }
	if err := os.Symlink(target, filepath.Join(source, backupPolicyMarkerPath)); err != nil { t.Fatal(err) }
	archive := filepath.Join(root, "backup.zip")
	if err := Create(source, archive); err == nil { t.Fatal("backup accepted symlink marker") }
	if _, err := os.Lstat(archive); !os.IsNotExist(err) { t.Fatalf("unsafe backup published: %v", err) }
}

func writePolicyMarkerArchive(t *testing.T, archive, marker string) {
	t.Helper()
	f, err := os.Create(archive)
	if err != nil { t.Fatal(err) }
	zw := zip.NewWriter(f)
	contents := map[string]string{
		"config.json": "{}",
		"delivery-policy.json": `{"initialized":true,"greylist":{},"rates":{}}`,
		backupPolicyMarkerPath: marker,
	}
	manifest := Manifest{Format: 1, Product: "SpamGate", Created: time.Now().UTC()}
	for name, body := range contents {
		w, err := zw.Create(name)
		if err != nil { t.Fatal(err) }
		if _, err := w.Write([]byte(body)); err != nil { t.Fatal(err) }
		digest := sha256.Sum256([]byte(body))
		manifest.Entries = append(manifest.Entries, Entry{Path: name, Bytes: int64(len(body)), SHA256: hex.EncodeToString(digest[:])})
	}
	w, err := zw.Create(manifestPath)
	if err != nil { t.Fatal(err) }
	if err := json.NewEncoder(w).Encode(manifest); err != nil { t.Fatal(err) }
	if err := zw.Close(); err != nil { t.Fatal(err) }
	if err := f.Close(); err != nil { t.Fatal(err) }
}

func TestForgedPolicyMarkerArchiveRefusedBeforeRestore(t *testing.T) {
	for _, tc := range []struct{name, marker string; valid bool}{
		{"wrong-version", "spamgate-delivery-policy-v2\n", false},
		{"truncated", "spamgate-delivery-policy-v1", false},
		{"extra-data", "spamgate-delivery-policy-v1\nextra", false},
		{"valid-control", backupPolicyMarkerText, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			archive := filepath.Join(root, "forged.zip")
			writePolicyMarkerArchive(t, archive, tc.marker)
			_, err := Verify(archive)
			if (err == nil) != tc.valid { t.Fatalf("Verify validity=%v err=%v", tc.valid, err) }
			dest := filepath.Join(root, "restored")
			err = Restore(archive, dest)
			if (err == nil) != tc.valid { t.Fatalf("Restore validity=%v err=%v", tc.valid, err) }
			if !tc.valid {
				if _, err := os.Lstat(dest); !os.IsNotExist(err) { t.Fatalf("unsafe restore published: %v", err) }
			} else {
				raw, err := os.ReadFile(filepath.Join(dest, backupPolicyMarkerPath))
				if err != nil || string(raw) != backupPolicyMarkerText { t.Fatal("valid marker did not roundtrip") }
			}
		})
	}
}
