//go:build linux

package main

import (
    "os"
    "syscall"
)

// O_NOFOLLOW prevents a symlink swap after Lstat. O_NONBLOCK prevents
// a swapped FIFO from hanging before the regular-file f.Stat check.
func openEvaluationCorpusDescriptor(path string) (*os.File, error) {
    fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
    if err != nil { return nil, err }
    return os.NewFile(uintptr(fd), path), nil
}
