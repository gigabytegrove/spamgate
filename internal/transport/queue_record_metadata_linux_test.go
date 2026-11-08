//go:build linux

package transport

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestValidateSpoolMetadataRejectsNilAndUnsafeRecords(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, strings.Repeat("a", 32)+".json")
	if err := os.WriteFile(path, []byte("{}"), 0600); err != nil { t.Fatal(err) }
	if err := validateSpoolMetadata(path, nil); err == nil { t.Fatal("nil inspection accepted") }
	info, err := os.Lstat(path)
	if err != nil { t.Fatal(err) }
	if err := validateSpoolMetadata(path, info); err != nil { t.Fatalf("valid original rejected: %v", err) }
	if err := os.Chmod(path, 0644); err != nil { t.Fatal(err) }
	if err := validateSpoolMetadata(path, info); err == nil { t.Fatal("public original accepted") }
	if err := os.Chmod(path, 0600); err != nil { t.Fatal(err) }
	link := filepath.Join(dir, "hardlink")
	if err := os.Link(path, link); err != nil { t.Fatal(err) }
	if err := validateSpoolMetadata(path, info); err == nil { t.Fatal("multiply linked original accepted") }
	if err := os.Remove(link); err != nil { t.Fatal(err) }
	if err := os.Remove(path); err != nil { t.Fatal(err) }
	if err := os.Symlink(link, path); err != nil { t.Fatal(err) }
	if err := validateSpoolMetadata(path, info); err == nil { t.Fatal("symlink accepted") }
}

func TestValidateSpoolMetadataRejectsRestoredMtimeRewrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, strings.Repeat("b", 32)+".json")
	if err := os.WriteFile(path, []byte("{}"), 0600); err != nil { t.Fatal(err) }
	before, err := os.Lstat(path)
	if err != nil { t.Fatal(err) }
	time.Sleep(1100 * time.Millisecond)
	if err := os.WriteFile(path, []byte("[]"), 0600); err != nil { t.Fatal(err) }
	if err := os.Chtimes(path, before.ModTime(), before.ModTime()); err != nil { t.Fatal(err) }
	after, err := os.Lstat(path)
	if err != nil { t.Fatal(err) }
	if !os.SameFile(before, after) || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
		t.Fatal("fixture must preserve inode, size and mtime")
	}
	if err := validateSpoolMetadata(path, before); err == nil {
		t.Fatal("same-inode rewrite with restored mtime accepted")
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "[]" { t.Fatalf("mutated original was lost: %q %v", data, err) }
}
