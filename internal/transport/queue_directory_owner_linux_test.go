//go:build linux

package transport

import (
    "os"
    "path/filepath"
    "strings"
    "syscall"
    "testing"
)

type queueOwnerFixture struct {
    os.FileInfo
    sys any
}
func (f queueOwnerFixture) Sys() any { return f.sys }

func TestDeliveryQueueOwnerMatchesEffectiveUID(t *testing.T) {
    path := filepath.Join(t.TempDir(), "delivery-queue")
    if err := os.Mkdir(path, 0700); err != nil { t.Fatal(err) }
    info, err := os.Lstat(path)
    if err != nil { t.Fatal(err) }
    if err := validateDeliveryQueueOwner(info); err != nil {
        t.Fatalf("owned private directory rejected: %v", err)
    }
}

func TestDeliveryQueueOwnerRejectsMismatchAndMissingMetadata(t *testing.T) {
    path := filepath.Join(t.TempDir(), "delivery-queue")
    if err := os.Mkdir(path, 0700); err != nil { t.Fatal(err) }
    info, err := os.Lstat(path)
    if err != nil { t.Fatal(err) }
    original, ok := info.Sys().(*syscall.Stat_t)
    if !ok { t.Fatal("Linux stat metadata unavailable") }
    different := *original
    different.Uid = uint32(os.Geteuid()) ^ 1
    if err := validateDeliveryQueueOwner(queueOwnerFixture{info, &different}); err == nil || !strings.Contains(err.Error(), "owner") {
        t.Fatalf("mismatched UID accepted or incorrectly diagnosed: %v", err)
    }
    if err := validateDeliveryQueueOwner(queueOwnerFixture{info, nil}); err == nil {
        t.Fatal("unverifiable owner accepted")
    }
    if err := validateDeliveryQueueOwner(nil); err == nil {
        t.Fatal("nil owner metadata accepted")
    }
}

func TestDeliveryQueueDirectoryOwnershipGate(t *testing.T) {
    path := filepath.Join(t.TempDir(), "delivery-queue")
    if err := os.Mkdir(path, 0700); err != nil { t.Fatal(err) }
    info, err := os.Lstat(path)
    if err != nil { t.Fatal(err) }
    original := info.Sys().(*syscall.Stat_t)
    different := *original
    different.Uid = uint32(os.Geteuid()) ^ 1
    if err := validateDeliveryQueueDirectory(queueOwnerFixture{info, &different}); err == nil {
        t.Fatal("private directory owned by another UID accepted")
    }
}
