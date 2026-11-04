//go:build linux

package backup

import (
 "os"
 "syscall"
)

// Do not follow a replaced symlink or block on a replaced FIFO between
// WalkDir/Lstat and open. The caller still validates the opened inode.
func openBackupSourceFile(path string) (*os.File, error) {
 fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_NOCTTY, 0)
 if err != nil { return nil, err }
 return os.NewFile(uintptr(fd), path), nil
}
