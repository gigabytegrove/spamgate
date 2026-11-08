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
    opened, err := f.Stat()
    if err != nil { return nil, fmt.Errorf("inspect opened queue record: %w", err) }
    if err := validateOpenedQueueRecordMetadata(opened); err != nil { return nil, fmt.Errorf("unsafe opened queue record: %w", err) }
    if !sameQueueRecordSnapshot(inspected, opened) {
        return nil, errors.New("opened queue record changed since inspection")
    }
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
    finished, err := f.Stat()
    if err != nil { return nil, fmt.Errorf("reinspect opened queue record: %w", err) }
    if err := validateOpenedQueueRecordMetadata(finished); err != nil { return nil, fmt.Errorf("unsafe completed queue record: %w", err) }
    if !sameQueueRecordSnapshot(opened, finished) || !sameQueueRecordSnapshot(after, finished) {
        return nil, errors.New("opened queue record metadata changed during read")
    }
    return raw, nil
}

// linuxOPath opens an inode for metadata inspection without opening the
// underlying FIFO, socket, or device for I/O. The constant is Linux O_PATH;
// Go's syscall package does not export it on supported Go versions.
const linuxOPath = 0x200000

// statQueueRecordAt inspects an inode relative to the verified directory
// without ever opening a special file for reading. O_NOFOLLOW with O_PATH
// yields a descriptor to a symlink itself; explicitly reject that inode.
func statQueueRecordAt(parent *os.File, name string) (os.FileInfo, error) {
    if parent == nil || !validQueueRecordName(name) {
        return nil, errors.New("invalid queue record inspection target")
    }
    fd, err := syscall.Openat(int(parent.Fd()), name, linuxOPath|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
    if err != nil { return nil, err }
    f := os.NewFile(uintptr(fd), name)
    if f == nil { _ = syscall.Close(fd); return nil, errors.New("cannot wrap queue record inspection descriptor") }
    defer f.Close()
    info, err := f.Stat()
    if err != nil { return nil, err }
    if info.Mode()&os.ModeSymlink != 0 {
        return nil, errors.New("queue record symlink is not permitted")
    }
    return info, nil
}

// sameQueueRecordSnapshot rejects same-inode mutations as well as replacement.
// It is a consistency guard, not a cryptographic integrity guarantee.
func sameQueueRecordSnapshot(a, b os.FileInfo) bool {
    return a != nil && b != nil && a.Mode().IsRegular() && b.Mode().IsRegular() &&
        os.SameFile(a, b) && a.Size() == b.Size() && a.ModTime().Equal(b.ModTime()) &&
        sameQueueRecordChangeTime(a, b)
}

 
// sameQueueRecordChangeTime compares Linux inode change timestamps, which
// advance when file contents or metadata change even if mtime is restored.
func sameQueueRecordChangeTime(a, b os.FileInfo) bool {
    if a == nil || b == nil { return false }
    left, ok := a.Sys().(*syscall.Stat_t)
    if !ok { return false }
    right, ok := b.Sys().(*syscall.Stat_t)
    if !ok { return false }
    return left.Ctim.Sec == right.Ctim.Sec && left.Ctim.Nsec == right.Ctim.Nsec
}

// validateOpenedQueueRecordMetadata checks the actual opened inode, not a
// pathname that can be replaced between Lstat and Openat. This mirrors the
// ownership, hard-link and privacy policy for on-disk spool originals.
func validateOpenedQueueRecordMetadata(info os.FileInfo) error {
    if info == nil || !info.Mode().IsRegular() {
        return errors.New("opened queue record must be a regular file")
    }
    if info.Mode().Perm()&0077 != 0 || info.Mode().Perm()&0400 == 0 ||
        info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
        return errors.New("opened queue record must be private, owner-readable and free of special permission bits")
    }
    native, ok := info.Sys().(*syscall.Stat_t)
    if !ok {
        return errors.New("opened queue record lacks native metadata")
    }
    if native.Nlink != 1 {
        return errors.New("opened queue record must have exactly one hard link")
    }
    if native.Uid != uint32(os.Geteuid()) {
        return errors.New("opened queue record must belong to the worker")
    }
    return nil
}
