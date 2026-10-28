package backup

import (
	"archive/zip"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOfflineBackupVerifyRestoreAndRefuseOverwrite(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "data")
	if err := os.MkdirAll(filepath.Join(source, "quarantine"), 0700); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"config.json": "{\"setup_complete\":true}", "events.jsonl": "{\"id\":\"one\"}\n", "quarantine/example.eml": "Subject: Test\r\n\r\nMessage\r\n", "fuzzy.json": "[1,2,3]"}
	for name, content := range want {
		if err := os.WriteFile(filepath.Join(source, name), []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	archive := filepath.Join(root, "sensitive-backup.zip")
	if err := Create(source, archive); err != nil {
		t.Fatal(err)
	}
	manifest, err := Verify(archive)
	if err != nil || len(manifest.Entries) != len(want) {
		t.Fatalf("verify returned %+v, %v", manifest, err)
	}
	stat, err := os.Stat(archive)
	if err != nil {
		t.Fatal(err)
	}
	if stat.Mode().Perm()&0077 != 0 {
		t.Fatalf("backup world-readable: %v", stat.Mode())
	}
	dest := filepath.Join(root, "restored")
	if err := Restore(archive, dest); err != nil {
		t.Fatal(err)
	}
	for name, expected := range want {
		b, err := os.ReadFile(filepath.Join(dest, name))
		if err != nil || string(b) != expected {
			t.Fatalf("restore file %s mismatch: %s, %v", name, b, err)
		}
	}
	if err := Restore(archive, dest); err == nil {
		t.Fatal("overwrote an existing install")
	}
	if err := Create(source, archive); err == nil {
		t.Fatal("overwrote backup")
	}
	if err := Create(source, filepath.Join(source, "backup.zip")); err == nil {
		t.Fatal("created backup inside live data")
	}
}
func TestBackupRejectsSymlinksAndBadArchives(t *testing.T) {
	root := t.TempDir()
	data := filepath.Join(root, "data")
	if err := os.MkdirAll(data, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(data, "config.json"), []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/etc/passwd", filepath.Join(data, "danger")); err != nil {
		t.Skip(err)
	}
	if err := Create(data, filepath.Join(root, "bad.zip")); err == nil {
		t.Fatal("followed symlink")
	}
	path := filepath.Join(root, "crafted.zip")
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	z := zip.NewWriter(file)
	w, err := z.Create("../escape.txt")
	if err != nil {
		t.Fatal(err)
	}
	w.Write([]byte("escape"))
	z.Close()
	file.Close()
	if _, err := Verify(path); err == nil || !strings.Contains(err.Error(), "unsafe") {
		t.Fatalf("accepted ZIP slip: %v", err)
	}
	if err := Restore(path, filepath.Join(root, "target")); err == nil {
		t.Fatal("restored malicious archive")
	}
}
func TestBackupDetectsCorruptedPayload(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "data")
	if err := os.MkdirAll(source, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "config.json"), []byte("valid backup"), 0600); err != nil {
		t.Fatal(err)
	}
	good := filepath.Join(root, "good.zip")
	if err := Create(source, good); err != nil {
		t.Fatal(err)
	}
	sourceZip, err := zip.OpenReader(good)
	if err != nil {
		t.Fatal(err)
	}
	defer sourceZip.Close()
	bad := filepath.Join(root, "tampered.zip")
	w, err := os.Create(bad)
	if err != nil {
		t.Fatal(err)
	}
	archive := zip.NewWriter(w)
	for _, f := range sourceZip.File {
		r, e := f.Open()
		if e != nil {
			t.Fatal(e)
		}
		content, e := io.ReadAll(r)
		r.Close()
		if e != nil {
			t.Fatal(e)
		}
		if f.Name == "config.json" {
			content = []byte("tamper backup")
		}
		dst, e := archive.Create(f.Name)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = dst.Write(content); e != nil {
			t.Fatal(e)
		}
	}
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(bad); err == nil {
		t.Fatal("failed to detect SHA-256 mismatch")
	}
}
