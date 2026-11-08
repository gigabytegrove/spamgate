//go:build linux

package transport

import (
    "errors"
    "fmt"
    "os"
    "path/filepath"
    "syscall"
)

// readQueueRecordAt opens the child relative to the validated directory
// descriptor. A substituted queue pathname cannot redirect the read.
func readQueueRecordAt(dir string, expected os.FileInfo, name string, inspected os.FileInfo) ([]byte, error) {
    if !validQueueRecordName(name) {
        return nil, errors.New("invalid queue record name")
    }
    parent, err := openVerifiedDeliveryQueueDirectory(dir, expected)
    if err != nil { return nil, err }
    defer parent.Close()
    fd, err := syscall.Openat(int(parent.Fd()), name, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
    if err != nil { return nil, fmt.Errorf("open queue record relative to verified spool: %w", err) }
    f := os.NewFile(uintptr(fd), name)
    if f == nil { _ = syscall.Close(fd); return nil, errors.New("cannot wrap queue record descriptor") }
    defer f.Close()
    // Check the child through the same verified parent descriptor used for the
    // read. A replacement of the parent pathname must not redirect metadata
    // validation to an unrelated spool.
    before, err := statQueueRecordAt(parent, name)
    if err != nil { return nil, fmt.Errorf("reinspect queue record before read: %w", err) }
    if !sameQueueRecordSnapshot(inspected, before) {
        return nil, errors.New("queue record identity changed before read")
    }
    // The descriptor-relative open protects the read from a substituted
    // parent pathname. Refuse a record that was unlinked or replaced while
    // being read, rather than returning bytes from a stale queue entry.
    raw, err := readOpenedSpoolFile(f, filepath.Join(dir, name), inspected)
    if err != nil { return nil, err }
    after, err := statQueueRecordAt(parent, name)
    if err != nil { return nil, fmt.Errorf("reinspect queue record after read: %w", err) }
    if !sameQueueRecordSnapshot(inspected, after) {
        return nil, errors.New("queue record pathname changed during read")
    }
    return raw, nil
}

// statQueueRecordAt inspects the child relative to the same verified parent
// descriptor. O_NONBLOCK prevents a malicious FIFO from stalling inspection;
// O_NOFOLLOW prevents symlink redirection. The caller still validates the
// actual reading descriptor independently.
func statQueueRecordAt(parent *os.File, name string) (os.FileInfo, error) {
    if !validQueueRecordName(name) { return nil, errors.New("invalid queue record name") }
    fd, err := syscall.Openat(int(parent.Fd()), name, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
    if err != nil { return nil, err }
    f := os.NewFile(uintptr(fd), name)
    if f == nil { _ = syscall.Close(fd); return nil, errors.New("cannot wrap queue record inspection descriptor") }
    defer f.Close()
    return f.Stat()
}

// sameQueueRecordSnapshot rejects same-inode mutations as well as replacement.
// It is a consistency guard, not a cryptographic integrity guarantee.
func sameQueueRecordSnapshot(a, b os.FileInfo) bool {
    return a != nil && b != nil && a.Mode().IsRegular() && b.Mode().IsRegular() &&
        os.SameFile(a, b) && a.Size() == b.Size() && a.ModTime().Equal(b.ModTime())
}
