//go:build linux

package transport

import (
    "errors"
    "fmt"
    "os"
    "syscall"
)

// removeQueueRecordAt unlinks through the verified spool directory descriptor,
// so a substituted parent pathname cannot redirect the deletion. It checks
// the child identity immediately before unlink. Linux unlinkat itself does
// not support an atomic inode-identity condition: a privileged concurrent
// writer replacing the child between check and unlink remains a residual risk.
func removeQueueRecordAt(dir string, expected os.FileInfo, name string, inspected os.FileInfo) error {
    if !validQueueRecordName(name) || inspected == nil || !inspected.Mode().IsRegular() {
        return errors.New("invalid queue record removal target")
    }
    parent, err := openVerifiedDeliveryQueueDirectory(dir, expected)
    if err != nil { return err }
    defer parent.Close()
    current, err := statQueueRecordAt(parent, name)
    if err != nil { return fmt.Errorf("inspect queue record before unlink: %w", err) }
    if !sameQueueRecordSnapshot(inspected, current) {
        return errors.New("queue record identity or metadata changed before unlink")
    }
    if err := syscall.Unlinkat(int(parent.Fd()), name); err != nil {
        return fmt.Errorf("unlink queue record relative to verified spool: %w", err)
    }
    return nil
}
