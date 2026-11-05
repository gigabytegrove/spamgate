//go:build !linux

package spoolaudit

import "os"

// Other platforms retain inode, size, mtime and digest validation.
// Native Linux ctime verification is intentionally not emulated.
func sameAuditChangeTime(_, _ os.FileInfo) bool { return true }
