//go:build linux

package transport

import (
    "os"
    "path/filepath"
    "strings"
    "testing"
    "time"
)

func TestRemoveQueueRecordAt(t *testing.T) {
    root := t.TempDir()
    dir := filepath.Join(root, "delivery-queue")
    if err := os.Mkdir(dir, 0700); err != nil { t.Fatal(err) }
    expected, err := captureDeliveryQueueIdentity(dir)
    if err != nil { t.Fatal(err) }
    name := strings.Repeat("a", 32) + ".json"
    path := filepath.Join(dir, name)
    if err := os.WriteFile(path, []byte("{}"), 0600); err != nil { t.Fatal(err) }
    inspected, err := os.Lstat(path)
    if err != nil { t.Fatal(err) }
    if err := removeQueueRecordAt(dir, expected, name, inspected); err != nil { t.Fatal(err) }
    if _, err := os.Lstat(path); !os.IsNotExist(err) { t.Fatalf("record not removed: %v", err) }
}

func TestRemoveQueueRecordAtRejectsReplacement(t *testing.T) {
    root := t.TempDir()
    dir := filepath.Join(root, "delivery-queue")
    if err := os.Mkdir(dir, 0700); err != nil { t.Fatal(err) }
    expected, err := captureDeliveryQueueIdentity(dir)
    if err != nil { t.Fatal(err) }
    name := strings.Repeat("b", 32) + ".json"
    path := filepath.Join(dir, name)
    if err := os.WriteFile(path, []byte("{}"), 0600); err != nil { t.Fatal(err) }
    inspected, err := os.Lstat(path)
    if err != nil { t.Fatal(err) }
    if err := os.Rename(path, filepath.Join(root, "old")); err != nil { t.Fatal(err) }
    if err := os.WriteFile(path, []byte("replacement"), 0600); err != nil { t.Fatal(err) }
    if err := removeQueueRecordAt(dir, expected, name, inspected); err == nil { t.Fatal("replacement accepted") }
    b, err := os.ReadFile(path)
    if err != nil || string(b) != "replacement" { t.Fatalf("replacement lost: %q %v", b, err) }
}

func TestRemoveQueueRecordAtRejectsParentReplacement(t *testing.T) {
    root := t.TempDir()
    dir := filepath.Join(root, "delivery-queue")
    if err := os.Mkdir(dir, 0700); err != nil { t.Fatal(err) }
    expected, err := captureDeliveryQueueIdentity(dir)
    if err != nil { t.Fatal(err) }
    name := strings.Repeat("c", 32) + ".json"
    path := filepath.Join(dir, name)
    if err := os.WriteFile(path, []byte("{}"), 0600); err != nil { t.Fatal(err) }
    inspected, err := os.Lstat(path)
    if err != nil { t.Fatal(err) }
    if err := os.Rename(dir, filepath.Join(root, "original")); err != nil { t.Fatal(err) }
    if err := os.Mkdir(dir, 0700); err != nil { t.Fatal(err) }
    if err := os.WriteFile(path, []byte("replacement"), 0600); err != nil { t.Fatal(err) }
    if err := removeQueueRecordAt(dir, expected, name, inspected); err == nil { t.Fatal("replacement directory accepted") }
    if _, err := os.Stat(path); err != nil { t.Fatalf("replacement record removed: %v", err) }
}

func TestRemoveQueueRecordAtRejectsSymlinkAndTraversal(t *testing.T) {
    root := t.TempDir()
    dir := filepath.Join(root, "delivery-queue")
    if err := os.Mkdir(dir, 0700); err != nil { t.Fatal(err) }
    expected, err := captureDeliveryQueueIdentity(dir)
    if err != nil { t.Fatal(err) }
    name := strings.Repeat("d", 32) + ".json"
    target := filepath.Join(root, "target")
    if err := os.WriteFile(target, []byte("keep"), 0600); err != nil { t.Fatal(err) }
    path := filepath.Join(dir, name)
    if err := os.Symlink(target, path); err != nil { t.Fatal(err) }
    inspected, err := os.Lstat(path)
    if err != nil { t.Fatal(err) }
    if err := removeQueueRecordAt(dir, expected, name, inspected); err == nil { t.Fatal("symlink accepted") }
    if err := removeQueueRecordAt(dir, expected, "../target", inspected); err == nil { t.Fatal("traversal accepted") }
    if _, err := os.Lstat(path); err != nil { t.Fatalf("symlink removed: %v", err) }
}


func TestRemoveQueueRecordAtRejectsInPlaceMutation(t *testing.T) {
    root := t.TempDir()
    dir := filepath.Join(root, "delivery-queue")
    if err := os.Mkdir(dir, 0700); err != nil { t.Fatal(err) }
    expected, err := captureDeliveryQueueIdentity(dir)
    if err != nil { t.Fatal(err) }
    name := strings.Repeat("e", 32) + ".json"
    path := filepath.Join(dir, name)
    if err := os.WriteFile(path, []byte("{}"), 0600); err != nil { t.Fatal(err) }
    inspected, err := os.Lstat(path)
    if err != nil { t.Fatal(err) }

    // Rewrite the same inode without replacing its directory entry.
    // Identity-only checks would incorrectly allow deletion.
    f, err := os.OpenFile(path, os.O_WRONLY|os.O_TRUNC, 0)
    if err != nil { t.Fatal(err) }
    if _, err := f.Write([]byte("{\"mutated\":true}")); err != nil { f.Close(); t.Fatal(err) }
    if err := f.Close(); err != nil { t.Fatal(err) }
    if err := removeQueueRecordAt(dir, expected, name, inspected); err == nil {
        t.Fatal("in-place changed record was removed")
    }
    b, err := os.ReadFile(path)
    if err != nil || string(b) != "{\"mutated\":true}" {
        t.Fatalf("modified original was lost: %q %v", b, err)
    }
}

func TestRemoveQueueRecordAtRejectsRestoredMtime(t *testing.T) {
    dir := t.TempDir()
    if err := os.Chmod(dir, 0700); err != nil { t.Fatal(err) }
    name := strings.Repeat("f", 32) + ".json"
    path := filepath.Join(dir, name)
    if err := os.WriteFile(path, []byte("{}"), 0600); err != nil { t.Fatal(err) }
    expected, err := captureDeliveryQueueIdentity(dir)
    if err != nil { t.Fatal(err) }
    before, err := os.Lstat(path)
    if err != nil { t.Fatal(err) }
    time.Sleep(1100 * time.Millisecond)
    if err := os.WriteFile(path, []byte("[]"), 0600); err != nil { t.Fatal(err) }
    if err := os.Chtimes(path, before.ModTime(), before.ModTime()); err != nil { t.Fatal(err) }
    after, err := os.Lstat(path)
    if err != nil { t.Fatal(err) }
    if !os.SameFile(before, after) || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
        t.Fatal("fixture did not restore inode, size and mtime")
    }
    if err := removeQueueRecordAt(dir, expected, name, before); err == nil {
        t.Fatal("cleanup removed modified record after mtime restoration")
    }
    data, err := os.ReadFile(path)
    if err != nil || string(data) != "[]" { t.Fatalf("modified record lost: %q %v", data, err) }
}
