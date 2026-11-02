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

func TestColdBackupRejectsWitnessedCountersWithoutMarker(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "data")
	if err := os.MkdirAll(source, 0700); err != nil { t.Fatal(err) }
	if err := os.WriteFile(filepath.Join(source, "config.json"), []byte("{}"), 0600); err != nil { t.Fatal(err) }
	original := []byte(`{"initialized":true,"greylist":{},"rates":{}}`)
	if err := os.WriteFile(filepath.Join(source, "delivery-policy.json"), original, 0600); err != nil { t.Fatal(err) }
	archive := filepath.Join(root, "unsafe.zip")
	if err := Create(source, archive); err == nil || !strings.Contains(err.Error(), "without initialization marker") {
		t.Fatalf("backup accepted witnessed counters without marker: %v", err)
	}
	if _, err := os.Lstat(archive); !os.IsNotExist(err) { t.Fatalf("unsafe backup published: %v", err) }
	after, err := os.ReadFile(filepath.Join(source, "delivery-policy.json"))
	if err != nil || string(after) != string(original) { t.Fatal("source evidence modified") }
}

func TestForgedArchiveWithWitnessButNoMarkerRefusedBeforeRestore(t *testing.T) {
	root := t.TempDir()
	archive := filepath.Join(root, "forged.zip")
	f, err := os.Create(archive)
	if err != nil { t.Fatal(err) }
	zw := zip.NewWriter(f)
	contents := map[string]string{
		"config.json": "{}",
		"delivery-policy.json": `{"initialized":true,"greylist":{},"rates":{}}`,
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
	if _, err := Verify(archive); err == nil || !strings.Contains(err.Error(), "without initialization marker") {
		t.Fatalf("forged archive passed verification: %v", err)
	}
	destination := filepath.Join(root, "restored")
	if err := Restore(archive, destination); err == nil || !strings.Contains(err.Error(), "without initialization marker") {
		t.Fatalf("forged archive restored: %v", err)
	}
	if _, err := os.Lstat(destination); !os.IsNotExist(err) { t.Fatalf("unsafe restore published: %v", err) }
}

func TestPolicyWitnessDecoderLegacyAndMalformed(t *testing.T) {
	cases := []struct{ name, raw string; witness bool; fail bool }{
		{"legacy", `{"greylist":{},"rates":{}}`, false, false},
		{"new", `{"initialized":true,"greylist":{},"rates":{}}`, true, false},
		{"false", `{"initialized":false,"greylist":{},"rates":{}}`, false, false},
		{"duplicate", `{"initialized":true,"initialized":false,"greylist":{},"rates":{}}`, false, true},
		{"null", `{"initialized":null,"greylist":{},"rates":{}}`, false, true},
		{"wrong type", `{"initialized":"true","greylist":{},"rates":{}}`, false, true},
		{"unknown", `{"initialized":true,"unexpected":0}`, false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := decodePolicyWitness(strings.NewReader(tc.raw))
			if (err != nil) != tc.fail || (!tc.fail && got != tc.witness) {
				t.Fatalf("witness=%v err=%v, want %v fail=%v", got, err, tc.witness, tc.fail)
			}
		})
	}
}
