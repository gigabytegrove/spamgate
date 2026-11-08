//go:build linux

package transport

import (
    "os"
    "path/filepath"
    "strings"
    "testing"
    "syscall"
    "time"
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

func TestStatQueueRecordAtRejectsUnsafeChildren(t *testing.T) {
    dir := t.TempDir()
    parent, err := os.Open(dir)
    if err != nil { t.Fatal(err) }
    defer parent.Close()
    name := strings.Repeat("f", 32) + ".json"
    path := filepath.Join(dir, name)
    if err := os.WriteFile(path, []byte("{}"), 0600); err != nil { t.Fatal(err) }
    original, err := statQueueRecordAt(parent, name)
    if err != nil { t.Fatal(err) }
    if !original.Mode().IsRegular() { t.Fatal("expected regular record") }
    if _, err := statQueueRecordAt(parent, "../"+name); err == nil { t.Fatal("traversal accepted") }
    if err := os.Remove(path); err != nil { t.Fatal(err) }
    if err := os.Symlink(filepath.Join(dir, "target"), path); err != nil { t.Fatal(err) }
    if _, err := statQueueRecordAt(parent, name); err == nil { t.Fatal("symlink accepted") }
    if err := os.Remove(path); err != nil { t.Fatal(err) }
    if err := syscall.Mkfifo(path, 0600); err != nil { t.Fatal(err) }
    fifo, err := statQueueRecordAt(parent, name)
    if err != nil { t.Fatal(err) }
    if fifo.Mode().IsRegular() { t.Fatal("FIFO misclassified as regular record") }
}

func TestStatQueueRecordAtRetainsVerifiedParentAfterRename(t *testing.T) {
    root := t.TempDir()
    dir := filepath.Join(root, "queue")
    if err := os.Mkdir(dir, 0700); err != nil { t.Fatal(err) }
    name := strings.Repeat("a", 32) + ".json"
    if err := os.WriteFile(filepath.Join(dir, name), []byte("original"), 0600); err != nil { t.Fatal(err) }
    parent, err := os.Open(dir)
    if err != nil { t.Fatal(err) }
    defer parent.Close()
    before, err := statQueueRecordAt(parent, name)
    if err != nil { t.Fatal(err) }
    if err := os.Rename(dir, filepath.Join(root, "moved")); err != nil { t.Fatal(err) }
    if err := os.Mkdir(dir, 0700); err != nil { t.Fatal(err) }
    if err := os.WriteFile(filepath.Join(dir, name), []byte("replacement"), 0600); err != nil { t.Fatal(err) }
    after, err := statQueueRecordAt(parent, name)
    if err != nil { t.Fatal(err) }
    if !os.SameFile(before, after) { t.Fatal("descriptor escaped to replacement parent") }
}


func TestReadQueueRecordAtRejectsInPlaceMutation(t *testing.T) {
    root := t.TempDir()
    dir := filepath.Join(root, "delivery-queue")
    if err := os.Mkdir(dir, 0700); err != nil { t.Fatal(err) }
    name := strings.Repeat("a", 32) + ".json"
    path := filepath.Join(dir, name)
    if err := os.WriteFile(path, []byte("{}"), 0600); err != nil { t.Fatal(err) }
    expected, err := captureDeliveryQueueIdentity(dir)
    if err != nil { t.Fatal(err) }
    inspected, err := os.Lstat(path)
    if err != nil { t.Fatal(err) }
    if err := os.WriteFile(path, []byte("{\"modified\":true}"), 0600); err != nil { t.Fatal(err) }
    current, err := os.Lstat(path)
    if err != nil { t.Fatal(err) }
    if !os.SameFile(inspected, current) { t.Fatal("fixture replaced inode") }
    if sameQueueRecordSnapshot(inspected, current) { t.Fatal("same-inode mutation considered unchanged") }
    if _, err := readQueueRecordAt(dir, expected, name, inspected); err == nil {
        t.Fatal("read accepted a record changed since inspection")
    }
    got, err := os.ReadFile(path)
    if err != nil || string(got) != "{\"modified\":true}" { t.Fatalf("original not retained: %q %v", got, err) }
}

func TestSameQueueRecordSnapshotRejectsNil(t *testing.T) {
    if sameQueueRecordSnapshot(nil, nil) { t.Fatal("nil snapshots accepted") }
}

// A same-size rewrite followed by an mtime restoration must not make the
// original inspection snapshot reusable for delivery or cleanup.
func TestSameQueueRecordSnapshotRejectsRestoredMtime(t *testing.T) {
    dir := t.TempDir()
    path := filepath.Join(dir, strings.Repeat("a", 32)+".json")
    if err := os.WriteFile(path, []byte("{}"), 0600); err != nil { t.Fatal(err) }
    before, err := os.Lstat(path)
    if err != nil { t.Fatal(err) }
    if !sameQueueRecordSnapshot(before, before) { t.Fatal("unchanged record rejected") }
    // Ensure the ctime clock advances on filesystems with coarse precision.
    time.Sleep(1100 * time.Millisecond)
    if err := os.WriteFile(path, []byte("[]"), 0600); err != nil { t.Fatal(err) }
    if err := os.Chtimes(path, before.ModTime(), before.ModTime()); err != nil { t.Fatal(err) }
    after, err := os.Lstat(path)
    if err != nil { t.Fatal(err) }
    if !os.SameFile(before, after) || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
        t.Fatal("fixture did not preserve inode, size, and mtime")
    }
    if sameQueueRecordSnapshot(before, after) { t.Fatal("restored mtime bypassed ctime guard") }
}

func TestReadQueueRecordAtRejectsRestoredMtimeMutation(t *testing.T) {
    dir := t.TempDir()
    if err := os.Chmod(dir, 0700); err != nil { t.Fatal(err) }
    name := strings.Repeat("b", 32) + ".json"
    path := filepath.Join(dir, name)
    if err := os.WriteFile(path, []byte("{}"), 0600); err != nil { t.Fatal(err) }
    parent, err := captureDeliveryQueueIdentity(dir)
    if err != nil { t.Fatal(err) }
    original, err := os.Lstat(path)
    if err != nil { t.Fatal(err) }
    time.Sleep(1100 * time.Millisecond)
    if err := os.WriteFile(path, []byte("[]"), 0600); err != nil { t.Fatal(err) }
    if err := os.Chtimes(path, original.ModTime(), original.ModTime()); err != nil { t.Fatal(err) }
    if _, err := readQueueRecordAt(dir, parent, name, original); err == nil {
        t.Fatal("read accepted same-inode rewrite with restored mtime")
    }
    got, err := os.ReadFile(path)
    if err != nil || string(got) != "[]" { t.Fatalf("mutated original not preserved: %q %v", got, err) }
}

func TestReadQueueRecordAtRejectsUnsafeInspectedSnapshot(t *testing.T) {
    dir := t.TempDir()
    if err := os.Chmod(dir, 0700); err != nil { t.Fatal(err) }
    name := strings.Repeat("c", 32) + ".json"
    path := filepath.Join(dir, name)
    if err := os.WriteFile(path, []byte("{}"), 0600); err != nil { t.Fatal(err) }
    parent, err := captureDeliveryQueueIdentity(dir)
    if err != nil { t.Fatal(err) }
    if _, err := readQueueRecordAt(dir, parent, name, nil); err == nil {
        t.Fatal("nil inspection accepted")
    }
    if _, err := os.Stat(path); err != nil { t.Fatalf("original lost: %v", err) }
}


func TestReadQueueRecordAtRejectsSpecialPermissionBits(t *testing.T) {
    dir := t.TempDir()
    if err := os.Chmod(dir, 0700); err != nil { t.Fatal(err) }
    name := strings.Repeat("d", 32) + ".json"
    path := filepath.Join(dir, name)
    if err := os.WriteFile(path, []byte("{}"), 0600); err != nil { t.Fatal(err) }
    expected, err := captureDeliveryQueueIdentity(dir)
    if err != nil { t.Fatal(err) }
    for _, tc := range []struct {
        name string
        bit os.FileMode
    }{
        {"setuid", os.ModeSetuid},
        {"setgid", os.ModeSetgid},
        {"sticky", os.ModeSticky},
    } {
        t.Run(tc.name, func(t *testing.T) {
            if err := os.Chmod(path, 0600|tc.bit); err != nil { t.Fatal(err) }
            inspected, err := os.Lstat(path)
            if err != nil { t.Fatal(err) }
            // Filesystems can strip privileged bits on chmod. Do not claim
            // rejection was exercised when the bit could not be persisted.
            if inspected.Mode()&tc.bit == 0 { t.Skip("filesystem stripped special mode bit") }
            if err := validateOpenedQueueRecordMetadata(inspected); err == nil {
                t.Fatal("special permission bit accepted by opened-inode validator")
            }
            if _, err := readQueueRecordAt(dir, expected, name, inspected); err == nil {
                t.Fatal("special permission bit accepted by queue reader")
            }
            data, err := os.ReadFile(path)
            if err != nil || string(data) != "{}" { t.Fatalf("original modified: %q %v", data, err) }
        })
    }
    if err := os.Chmod(path, 0600); err != nil { t.Fatal(err) }
    inspected, err := os.Lstat(path)
    if err != nil { t.Fatal(err) }
    if _, err := readQueueRecordAt(dir, expected, name, inspected); err != nil {
        t.Fatalf("private ordinary queue record rejected: %v", err)
    }
}
