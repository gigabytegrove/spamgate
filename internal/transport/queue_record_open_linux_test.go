//go:build linux

package transport

import (
    "os"
    "path/filepath"
    "strings"
    "testing"
)

func TestReadQueueRecordAtVerifiedDirectory(t *testing.T) {
    root := t.TempDir()
    dir := filepath.Join(root, "delivery-queue")
    if err := os.Mkdir(dir, 0700); err != nil { t.Fatal(err) }
    expected, err := captureDeliveryQueueIdentity(dir)
    if err != nil { t.Fatal(err) }
    name := strings.Repeat("a", 32) + ".json"
    original := filepath.Join(dir, name)
    if err := os.WriteFile(original, []byte("{}"), 0600); err != nil { t.Fatal(err) }
    meta, err := os.Lstat(original)
    if err != nil { t.Fatal(err) }
    got, err := readQueueRecordAt(dir, expected, name, meta)
    if err != nil { t.Fatal(err) }
    if string(got) != "{}" { t.Fatalf("unexpected record %q", got) }
    if _, err := readQueueRecordAt(dir, expected, "../outside", meta); err == nil {
        t.Fatal("path traversal accepted")
    }
    if err := os.Rename(dir, filepath.Join(root, "original")); err != nil { t.Fatal(err) }
    if err := os.Mkdir(dir, 0700); err != nil { t.Fatal(err) }
    if err := os.WriteFile(filepath.Join(dir, name), []byte("{}"), 0600); err != nil { t.Fatal(err) }
    if _, err := readQueueRecordAt(dir, expected, name, meta); err == nil {
        t.Fatal("replacement queue directory accepted")
    }
}

func TestReadQueueRecordAtRejectsSymlinkChild(t *testing.T) {
    root := t.TempDir()
    dir := filepath.Join(root, "delivery-queue")
    if err := os.Mkdir(dir, 0700); err != nil { t.Fatal(err) }
    expected, err := captureDeliveryQueueIdentity(dir)
    if err != nil { t.Fatal(err) }
    target := filepath.Join(root, "target")
    if err := os.WriteFile(target, []byte("{}"), 0600); err != nil { t.Fatal(err) }
    name := strings.Repeat("b", 32) + ".json"
    if err := os.Symlink(target, filepath.Join(dir, name)); err != nil { t.Fatal(err) }
    meta, err := os.Lstat(filepath.Join(dir, name))
    if err != nil { t.Fatal(err) }
    if _, err := readQueueRecordAt(dir, expected, name, meta); err == nil {
        t.Fatal("symlink queue record accepted")
    }
}

func TestReadQueueRecordAtIndependentOfWorkingDirectory(t *testing.T) {
    root := t.TempDir()
    dir := filepath.Join(root, "delivery-queue")
    if err := os.Mkdir(dir, 0700); err != nil { t.Fatal(err) }
    name := strings.Repeat("c", 32) + ".json"
    record := filepath.Join(dir, name)
    if err := os.WriteFile(record, []byte("{}"), 0600); err != nil { t.Fatal(err) }
    expected, err := captureDeliveryQueueIdentity(dir)
    if err != nil { t.Fatal(err) }
    inspected, err := os.Lstat(record)
    if err != nil { t.Fatal(err) }
    // No process chdir: the metadata validator must receive the absolute
    // spool pathname even if a same-named child exists elsewhere.
    other := filepath.Join(root, "unrelated")
    if err := os.Mkdir(other, 0700); err != nil { t.Fatal(err) }
    if err := os.WriteFile(filepath.Join(other, name), []byte("different"), 0600); err != nil { t.Fatal(err) }
    got, err := readQueueRecordAt(dir, expected, name, inspected)
    if err != nil { t.Fatalf("absolute metadata lookup required: %v", err) }
    if string(got) != "{}" { t.Fatalf("wrong spool record: %q", got) }
}

func TestReadQueueRecordAtRejectsReplacedRecord(t *testing.T) {
    root := t.TempDir()
    dir := filepath.Join(root, "delivery-queue")
    if err := os.Mkdir(dir, 0700); err != nil { t.Fatal(err) }
    name := strings.Repeat("d", 32) + ".json"
    path := filepath.Join(dir, name)
    if err := os.WriteFile(path, []byte("{}"), 0600); err != nil { t.Fatal(err) }
    expected, err := captureDeliveryQueueIdentity(dir)
    if err != nil { t.Fatal(err) }
    inspected, err := os.Lstat(path)
    if err != nil { t.Fatal(err) }
    if err := os.Rename(path, filepath.Join(root, "original")); err != nil { t.Fatal(err) }
    if err := os.WriteFile(path, []byte("{}"), 0600); err != nil { t.Fatal(err) }
    if _, err := readQueueRecordAt(dir, expected, name, inspected); err == nil {
        t.Fatal("replaced queue record accepted")
    }
}

func TestReadQueueRecordAtRejectsUnlinkedRecord(t *testing.T) {
    root := t.TempDir()
    dir := filepath.Join(root, "delivery-queue")
    if err := os.Mkdir(dir, 0700); err != nil { t.Fatal(err) }
    name := strings.Repeat("e", 32) + ".json"
    path := filepath.Join(dir, name)
    if err := os.WriteFile(path, []byte("{}"), 0600); err != nil { t.Fatal(err) }
    expected, err := captureDeliveryQueueIdentity(dir)
    if err != nil { t.Fatal(err) }
    inspected, err := os.Lstat(path)
    if err != nil { t.Fatal(err) }
    if err := os.Remove(path); err != nil { t.Fatal(err) }
    if _, err := readQueueRecordAt(dir, expected, name, inspected); err == nil {
        t.Fatal("unlinked queue record accepted")
    }
}
