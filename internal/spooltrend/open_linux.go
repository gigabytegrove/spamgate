//go:build linux

package spooltrend

import (
 "os"
 "syscall"
)

// openEvidence refuses symlinks at the final component and avoids blocking on
// a substituted FIFO/device. Load separately verifies regular-file identity.
func openEvidence(path string) (*os.File, error) {
 fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC|syscall.O_NONBLOCK, 0)
 if err != nil { return nil, err }
 return os.NewFile(uintptr(fd), path), nil
}
