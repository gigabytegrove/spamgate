package transport

import (
    "os"
    "path/filepath"
    "strings"
    "testing"
)

func TestInspectDeliveryQueueIdentityOpenedDirectory(t *testing.T) {
    dir := filepath.Join(t.TempDir(), "spool")
    if err := os.Mkdir(dir, 0700); err != nil { t.Fatal(err) }
    opened, err := inspectDeliveryQueueIdentity(dir)
    if err != nil { t.Fatal(err) }
    current, err := os.Lstat(dir)
    if err != nil { t.Fatal(err) }
    if !os.SameFile(opened, current) {
        t.Fatal("captured identity is not the directory on disk")
    }
    if err := checkDeliveryQueueIdentity(dir, opened); err != nil { t.Fatal(err) }
}

func TestInspectDeliveryQueueIdentityRejectsUnsafePaths(t *testing.T) {
    parent := t.TempDir()
    dir := filepath.Join(parent, "spool")
    if err := os.Mkdir(dir, 0700); err != nil { t.Fatal(err) }
    original, err := captureDeliveryQueueIdentity(dir)
    if err != nil { t.Fatal(err) }
    if err := os.Chmod(dir, 0755); err != nil { t.Fatal(err) }
    if _, err := inspectDeliveryQueueIdentity(dir); err == nil {
        t.Fatal("world-accessible spool was accepted")
    }
    if err := os.Chmod(dir, 0700); err != nil { t.Fatal(err) }
    moved := filepath.Join(parent, "moved")
    if err := os.Rename(dir, moved); err != nil { t.Fatal(err) }
    if err := os.Mkdir(dir, 0700); err != nil { t.Fatal(err) }
    if err := checkDeliveryQueueIdentity(dir, original); err == nil || !strings.Contains(err.Error(), "identity changed") {
        t.Fatalf("replaced directory accepted: %v", err)
    }
    if err := os.Remove(dir); err != nil { t.Fatal(err) }
    if err := os.Symlink(moved, dir); err != nil { t.Fatal(err) }
    if _, err := inspectDeliveryQueueIdentity(dir); err == nil {
        t.Fatal("symlink spool was accepted")
    }
    if err := os.Remove(dir); err != nil { t.Fatal(err) }
    if err := os.WriteFile(dir, []byte("not a directory"), 0600); err != nil { t.Fatal(err) }
    if _, err := inspectDeliveryQueueIdentity(dir); err == nil {
        t.Fatal("regular file was accepted as spool")
    }
}

func TestCheckDeliveryQueueIdentityUninitialized(t *testing.T) {
    if err := checkDeliveryQueueIdentity(t.TempDir(), nil); err == nil {
        t.Fatal("missing startup identity accepted")
    }
}
