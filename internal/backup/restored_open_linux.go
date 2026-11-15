//go:build linux

package backup

import (
 "os"
 "syscall"
)

// Do not follow a final-component symlink introduced after Lstat.
// O_CLOEXEC avoids leaking backup descriptors into child processes.
func openRestoredRegularNoFollow(path string) (*os.File, error) {
 fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
 if err != nil { return nil, err }
 return os.NewFile(uintptr(fd), path), nil
}
