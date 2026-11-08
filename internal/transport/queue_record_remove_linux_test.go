//go:build linux

package transport

import (
    "os"
    "path/filepath"
    "strings"
    "testing"
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
