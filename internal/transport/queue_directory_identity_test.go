package transport

import (
    "os"
    "path/filepath"
    "strings"
    "testing"
)

func TestDeliveryQueueDirectoryIdentitySurvivesNormalUse(t *testing.T) {
    dir := filepath.Join(t.TempDir(), "delivery-queue")
    if err := os.Mkdir(dir, 0700); err != nil { t.Fatal(err) }
    identity, err := captureDeliveryQueueIdentity(dir)
    if err != nil { t.Fatal(err) }
    if err := checkDeliveryQueueIdentity(dir, identity); err != nil { t.Fatal(err) }
    q := &DeliveryQueue{dir: dir, dirIdentity: identity}
    if _, err := q.Snapshot(); err != nil { t.Fatalf("valid empty spool: %v", err) }
}

func TestDeliveryQueueDirectoryIdentityRejectsReplacement(t *testing.T) {
    parent := t.TempDir()
    dir := filepath.Join(parent, "delivery-queue")
    if err := os.Mkdir(dir, 0700); err != nil { t.Fatal(err) }
    identity, err := captureDeliveryQueueIdentity(dir)
    if err != nil { t.Fatal(err) }
    old := filepath.Join(parent, "original")
    if err := os.Rename(dir, old); err != nil { t.Fatal(err) }
    if err := os.Mkdir(dir, 0700); err != nil { t.Fatal(err) }
    q := &DeliveryQueue{dir: dir, dirIdentity: identity}
    if _, err := q.Snapshot(); err == nil || !strings.Contains(err.Error(), "identity changed") {
        t.Fatalf("snapshot must reject replaced spool directory: %v", err)
    }
    if err := q.put(spoolRecord{}); err == nil || !strings.Contains(err.Error(), "identity changed") {
        t.Fatalf("publication must reject replaced spool directory: %v", err)
    }
    if _, err := q.get(strings.Repeat("a", 32)); err == nil || !strings.Contains(err.Error(), "identity changed") {
        t.Fatalf("recovery must reject replaced spool directory: %v", err)
    }
}

func TestDeliveryQueueDirectoryIdentityRejectsMissingAndSymlink(t *testing.T) {
    parent := t.TempDir()
    dir := filepath.Join(parent, "delivery-queue")
    if err := os.Mkdir(dir, 0700); err != nil { t.Fatal(err) }
    identity, err := captureDeliveryQueueIdentity(dir)
    if err != nil { t.Fatal(err) }
    if err := os.Remove(dir); err != nil { t.Fatal(err) }
    if err := checkDeliveryQueueIdentity(dir, identity); err == nil {
        t.Fatal("missing spool directory accepted")
    }
    target := filepath.Join(parent, "other")
    if err := os.Mkdir(target, 0700); err != nil { t.Fatal(err) }
    if err := os.Symlink(target, dir); err != nil { t.Fatal(err) }
    if err := checkDeliveryQueueIdentity(dir, identity); err == nil {
        t.Fatal("symlink replacement accepted")
    }
}

func TestDeliveryQueueDirectoryIdentityRejectsPermissionDrift(t *testing.T) {
    dir := filepath.Join(t.TempDir(), "delivery-queue")
    if err := os.Mkdir(dir, 0700); err != nil { t.Fatal(err) }
    identity, err := captureDeliveryQueueIdentity(dir)
    if err != nil { t.Fatal(err) }
    if err := os.Chmod(dir, 0755); err != nil { t.Fatal(err) }
    if err := checkDeliveryQueueIdentity(dir, identity); err == nil {
        t.Fatal("world-accessible spool accepted after startup")
    }
}
