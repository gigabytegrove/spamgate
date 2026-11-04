//go:build linux

package backup

import (
    "os"
    "syscall"
)

// sourceChangeTimeEqual detects same-size rewrites even if mtime is restored.
// Linux ctime is updated by the kernel when inode contents or metadata change.
func sourceChangeTimeEqual(before, after os.FileInfo) bool {
    a, okA := before.Sys().(*syscall.Stat_t)
    b, okB := after.Sys().(*syscall.Stat_t)
    if !okA || !okB {
        return false // Fail closed when inode metadata is unavailable.
    }
    return a.Ctim.Sec == b.Ctim.Sec && a.Ctim.Nsec == b.Ctim.Nsec
}
