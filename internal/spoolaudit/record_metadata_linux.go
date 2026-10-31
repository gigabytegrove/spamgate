//go:build linux

package spoolaudit

import (
    "errors"
    "fmt"
    "os"
    "syscall"
)

// Match the Linux transport's private, single-link spool ownership policy.
// The audit remains read-only; an unsafe original is reported, never repaired.
func validateAuditRecordMetadata(path string, inspected os.FileInfo) error {
    if !inspected.Mode().IsRegular() {
        return errors.New("spool object is not a regular file")
    }
    current, err := os.Lstat(path)
    if err != nil {
        return fmt.Errorf("inspect spool pathname: %w", err)
    }
    if !current.Mode().IsRegular() || !os.SameFile(inspected, current) {
        return errors.New("spool pathname changed or is not a regular file")
    }
    if current.Mode().Perm()&0077 != 0 || current.Mode().Perm()&0400 == 0 {
        return errors.New("spool original must be private and owner-readable")
    }
    stat, ok := current.Sys().(*syscall.Stat_t)
    if !ok {
        return errors.New("cannot inspect native spool ownership")
    }
    if stat.Nlink != 1 {
        return errors.New("spool original must have exactly one hard link")
    }
    if stat.Uid != uint32(os.Geteuid()) {
        return errors.New("spool original must belong to the worker")
    }
    return nil
}
