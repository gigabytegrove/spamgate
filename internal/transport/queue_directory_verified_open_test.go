package transport

import (
    "os"
    "path/filepath"
    "testing"
)

func TestOpenVerifiedDeliveryQueueDirectory(t *testing.T) {
    dir := filepath.Join(t.TempDir(), "delivery-queue")
    if err := os.Mkdir(dir, 0700); err != nil { t.Fatal(err) }
    expected, err := captureDeliveryQueueIdentity(dir)
    if err != nil { t.Fatal(err) }
    f, err := openVerifiedDeliveryQueueDirectory(dir, expected)
    if err != nil { t.Fatal(err) }
    actual, err := f.Stat()
    if err != nil { t.Fatal(err) }
    if !os.SameFile(expected, actual) { t.Fatal("opened unexpected directory") }
    if err := f.Close(); err != nil { t.Fatal(err) }
}

func TestOpenVerifiedDeliveryQueueDirectoryRejectsReplacement(t *testing.T) {
    root := t.TempDir()
    dir := filepath.Join(root, "delivery-queue")
    if err := os.Mkdir(dir, 0700); err != nil { t.Fatal(err) }
    expected, err := captureDeliveryQueueIdentity(dir)
    if err != nil { t.Fatal(err) }
    if err := os.Rename(dir, filepath.Join(root, "original")); err != nil { t.Fatal(err) }
    if err := os.Mkdir(dir, 0700); err != nil { t.Fatal(err) }
    if f, err := openVerifiedDeliveryQueueDirectory(dir, expected); err == nil {
        _ = f.Close()
        t.Fatal("replacement directory accepted")
    }
}

func TestOpenVerifiedDeliveryQueueDirectoryRejectsSymlinkAndPermissionDrift(t *testing.T) {
    root := t.TempDir()
    dir := filepath.Join(root, "delivery-queue")
    if err := os.Mkdir(dir, 0700); err != nil { t.Fatal(err) }
    expected, err := captureDeliveryQueueIdentity(dir)
    if err != nil { t.Fatal(err) }
    if err := os.Chmod(dir, 0755); err != nil { t.Fatal(err) }
    if f, err := openVerifiedDeliveryQueueDirectory(dir, expected); err == nil {
        _ = f.Close()
        t.Fatal("permission drift accepted")
    }
    if err := os.Chmod(dir, 0700); err != nil { t.Fatal(err) }
    moved := filepath.Join(root, "original")
    if err := os.Rename(dir, moved); err != nil { t.Fatal(err) }
    if err := os.Symlink(moved, dir); err != nil { t.Fatal(err) }
    if f, err := openVerifiedDeliveryQueueDirectory(dir, expected); err == nil {
        _ = f.Close()
        t.Fatal("symlink accepted")
    }
}

func TestOpenVerifiedDeliveryQueueDirectoryRejectsNilIdentity(t *testing.T) {
    if f, err := openVerifiedDeliveryQueueDirectory(t.TempDir(), nil); err == nil {
        _ = f.Close()
        t.Fatal("nil identity accepted")
    }
}
