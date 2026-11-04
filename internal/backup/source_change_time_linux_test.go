//go:build linux

package backup

import (
    "os"
    "path/filepath"
    "testing"
    "time"
)

func TestSourceChangeTimeDetectsRestoredMtimeRewrite(t *testing.T) {
    path := filepath.Join(t.TempDir(), "message.eml")
    if err := os.WriteFile(path, []byte("original"), 0600); err != nil { t.Fatal(err) }
    old := time.Unix(1700000000, 0)
    if err := os.Chtimes(path, old, old); err != nil { t.Fatal(err) }
    before, err := os.Stat(path)
    if err != nil { t.Fatal(err) }
    if !sourceChangeTimeEqual(before, before) { t.Fatal("identical snapshot rejected") }
    // Ensure a distinguishable ctime even on filesystems with coarse timestamps.
    time.Sleep(15 * time.Millisecond)
    if err := os.WriteFile(path, []byte("modified"), 0600); err != nil { t.Fatal(err) }
    if err := os.Chtimes(path, old, old); err != nil { t.Fatal(err) }
    after, err := os.Stat(path)
    if err != nil { t.Fatal(err) }
    if !os.SameFile(before, after) || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
        t.Fatal("test preconditions failed: identity, size and mtime must match")
    }
    if sourceChangeTimeEqual(before, after) { t.Fatal("same-size rewrite with restored mtime escaped detection") }
}

func TestSourceChangeTimeRejectsMissingMetadata(t *testing.T) {
    if sourceChangeTimeEqual(fakeFileInfo{}, fakeFileInfo{}) { t.Fatal("missing inode metadata accepted") }
}

type fakeFileInfo struct{}
func (fakeFileInfo) Name() string { return "fake" }
func (fakeFileInfo) Size() int64 { return 0 }
func (fakeFileInfo) Mode() os.FileMode { return 0600 }
func (fakeFileInfo) ModTime() time.Time { return time.Time{} }
func (fakeFileInfo) IsDir() bool { return false }
func (fakeFileInfo) Sys() any { return nil }
