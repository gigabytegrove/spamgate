//go:build linux

package transport

import (
    "errors"
    "fmt"
    "os"
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
    return readOpenedSpoolFile(f, name, inspected)
}
