//go:build linux

package spoolaudit

import (
 "os"
 "syscall"
)

// Linux ctime detects metadata and in-place writes even when an actor
// restores mtime and preserves the byte length. It is not creation time.
func sameAuditChangeTime(a, b os.FileInfo) bool {
 left, okA := a.Sys().(*syscall.Stat_t)
 right, okB := b.Sys().(*syscall.Stat_t)
 if !okA || !okB { return false }
 return left.Ctim.Sec == right.Ctim.Sec && left.Ctim.Nsec == right.Ctim.Nsec
}
