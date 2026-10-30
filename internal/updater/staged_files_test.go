package updater

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAtomicUpdateMetadataDoesNotFollowSymlink(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "updates")
	if err := os.Mkdir(dir, 0700); err != nil { t.Fatal(err) }
	victim := filepath.Join(root, "config.json")
	if err := os.WriteFile(victim, []byte("keep-this-config"), 0600); err != nil { t.Fatal(err) }
	target := filepath.Join(dir, "pending.json")
	if err := os.Symlink(victim, target); err != nil { t.Skip(err) }
	if err := atomicUpdateFile(dir, "pending.json", []byte("new-metadata"), 0600); err != nil { t.Fatal(err) }
	got, err := os.ReadFile(victim)
	if err != nil || string(got) != "keep-this-config" {
		t.Fatalf("staging overwrote a symlink target: %q %v", got, err)
	}
	info, err := os.Lstat(target)
	if err != nil || !info.Mode().IsRegular() {
		t.Fatalf("metadata was not atomically published as a regular file: %v %v", info, err)
	}
	got, err = os.ReadFile(target)
	if err != nil || string(got) != "new-metadata" { t.Fatalf("bad published metadata: %q %v", got, err) }
	if info.Mode().Perm()&0077 != 0 { t.Fatalf("metadata permissions too broad: %v", info.Mode()) }
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 { t.Fatalf("staging leftovers: %v %v", entries, err) }
}

func TestPendingRejectsSymlinkedAndOversizedMetadata(t *testing.T) {
	dir := t.TempDir()
	stageTestBinary(t, dir)
	base := updateDir(dir)
	metadata := filepath.Join(base, "pending.json")
	good, err := os.ReadFile(metadata)
	if err != nil { t.Fatal(err) }
	realMetadata := filepath.Join(dir, "external.json")
	if err := os.WriteFile(realMetadata, good, 0600); err != nil { t.Fatal(err) }
	if err := os.Remove(metadata); err != nil { t.Fatal(err) }
	if err := os.Symlink(realMetadata, metadata); err != nil { t.Skip(err) }
	if _, _, err := Pending(dir); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("symlinked pending metadata accepted: %v", err)
	}
	if err := os.Remove(metadata); err != nil { t.Fatal(err) }
	if err := os.WriteFile(metadata, bytes.Repeat([]byte("x"), 4097), 0600); err != nil { t.Fatal(err) }
	if _, _, err := Pending(dir); err == nil || !strings.Contains(err.Error(), "size limit") {
		t.Fatalf("oversized pending metadata accepted: %v", err)
	}
	if err := os.WriteFile(metadata, good, 0600); err != nil { t.Fatal(err) }
	if _, _, err := Pending(dir); err != nil { t.Fatalf("valid staged metadata rejected: %v", err) }
}

func TestPendingRejectsSymlinkedBinary(t *testing.T) {
	dir := t.TempDir()
	stageTestBinary(t, dir)
	name, err := platformAsset()
	if err != nil { t.Skip(err) }
	target := filepath.Join(updateDir(dir), "pending"+filepath.Ext(name))
	external := filepath.Join(dir, "external-binary")
	binary, err := os.ReadFile(target)
	if err != nil { t.Fatal(err) }
	if err := os.WriteFile(external, binary, 0700); err != nil { t.Fatal(err) }
	if err := os.Remove(target); err != nil { t.Fatal(err) }
	if err := os.Symlink(external, target); err != nil { t.Skip(err) }
	if _, _, err := Pending(dir); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("symlinked staged binary accepted: %v", err)
	}
}

func TestUpdateDirectorySymlinkAndPermissionsRefused(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(root, "outside")
	if err := os.Mkdir(outside, 0700); err != nil { t.Fatal(err) }
	link := filepath.Join(root, "updates")
	if err := os.Symlink(outside, link); err != nil { t.Skip(err) }
	if err := ensureUpdateDir(link, true); err == nil {
		t.Fatal("accepted symlinked updates directory")
	}
	if err := atomicUpdateFile(link, "pending.json", []byte("unsafe"), 0600); err == nil {
		t.Fatal("wrote through symlinked updates directory")
	}
	if _, err := os.Stat(filepath.Join(outside, "pending.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("symlink target was modified: %v", err)
	}
	if err := os.Remove(link); err != nil { t.Fatal(err) }
	if err := os.Mkdir(link, 0777); err != nil { t.Fatal(err) }
	if err := os.Chmod(link, 0777); err != nil { t.Fatal(err) }
	if err := ensureUpdateDir(link, false); err == nil {
		t.Fatal("accepted group/world-writable update directory")
	}
}

func TestUpdateRecordDoesNotOverwriteSymlinkTarget(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(updateDir(dir), 0700); err != nil { t.Fatal(err) }
	victim := filepath.Join(dir, "config.json")
	if err := os.WriteFile(victim, []byte("unchanged"), 0600); err != nil { t.Fatal(err) }
	if err := os.Symlink(victim, lastRecordPath(dir)); err != nil { t.Skip(err) }
	if err := Record(dir, "checking", "v0.6.0-beta.1", "native update in progress"); err != nil { t.Fatal(err) }
	b, err := os.ReadFile(victim)
	if err != nil || string(b) != "unchanged" { t.Fatalf("update record corrupted config: %q %v", b, err) }
	record, err := LastRecord(dir)
	if err != nil || record == nil || record.State != "checking" { t.Fatalf("invalid update record: %+v %v", record, err) }
}
