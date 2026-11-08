//go:build linux

package transport

import (
    "os"
    "path/filepath"
    "strings"
    "testing"
)

func TestOpenedQueueRecordMetadataEnforcesPrivacyAndHardlinks(t *testing.T) {
    dir := t.TempDir()
    path := filepath.Join(dir, strings.Repeat("a", 32)+".json")
    if err := os.WriteFile(path, []byte("{}"), 0600); err != nil { t.Fatal(err) }
    stat := func() os.FileInfo {
        t.Helper()
        info, err := os.Stat(path)
        if err != nil { t.Fatal(err) }
        return info
    }
    if err := validateOpenedQueueRecordMetadata(stat()); err != nil { t.Fatalf("private record rejected: %v", err) }
    if err := os.Chmod(path, 0644); err != nil { t.Fatal(err) }
    if err := validateOpenedQueueRecordMetadata(stat()); err == nil { t.Fatal("world-readable record accepted") }
    if err := os.Chmod(path, 0200); err != nil { t.Fatal(err) }
    if err := validateOpenedQueueRecordMetadata(stat()); err == nil { t.Fatal("owner-unreadable record accepted") }
    if err := os.Chmod(path, 0600); err != nil { t.Fatal(err) }
    link := filepath.Join(dir, "additional-link")
    if err := os.Link(path, link); err != nil { t.Fatal(err) }
    if err := validateOpenedQueueRecordMetadata(stat()); err == nil { t.Fatal("multiply-linked record accepted") }
    if err := os.Remove(link); err != nil { t.Fatal(err) }
    if err := validateOpenedQueueRecordMetadata(stat()); err != nil { t.Fatalf("restored private record rejected: %v", err) }
    if err := validateOpenedQueueRecordMetadata(nil); err == nil { t.Fatal("nil record accepted") }
}

func TestReadQueueRecordAtRejectsNewHardlinkAfterInspection(t *testing.T) {
    dir := t.TempDir()
    if err := os.Chmod(dir, 0700); err != nil { t.Fatal(err) }
    name := strings.Repeat("b", 32)+".json"
    path := filepath.Join(dir, name)
    if err := os.WriteFile(path, []byte("{}"), 0600); err != nil { t.Fatal(err) }
    parent, err := captureDeliveryQueueIdentity(dir)
    if err != nil { t.Fatal(err) }
    before, err := os.Lstat(path)
    if err != nil { t.Fatal(err) }
    link := filepath.Join(t.TempDir(), "external-link")
    if err := os.Link(path, link); err != nil { t.Fatal(err) }
    if _, err := readQueueRecordAt(dir, parent, name, before); err == nil {
        t.Fatal("record with new hard link accepted")
    }
    if got, err := os.ReadFile(path); err != nil || string(got) != "{}" {
        t.Fatalf("original modified: %q %v", got, err)
    }
}

func TestRemoveQueueRecordAtRejectsNewHardlinkAfterInspection(t *testing.T) {
    dir := t.TempDir()
    if err := os.Chmod(dir, 0700); err != nil { t.Fatal(err) }
    name := strings.Repeat("c", 32)+".json"
    path := filepath.Join(dir, name)
    if err := os.WriteFile(path, []byte("{}"), 0600); err != nil { t.Fatal(err) }
    parent, err := captureDeliveryQueueIdentity(dir)
    if err != nil { t.Fatal(err) }
    before, err := os.Lstat(path)
    if err != nil { t.Fatal(err) }
    link := filepath.Join(t.TempDir(), "external-link")
    if err := os.Link(path, link); err != nil { t.Fatal(err) }
    if err := removeQueueRecordAt(dir, parent, name, before); err == nil {
        t.Fatal("multiply-linked queue record removed")
    }
    if _, err := os.Stat(path); err != nil { t.Fatalf("original removed: %v", err) }
}
