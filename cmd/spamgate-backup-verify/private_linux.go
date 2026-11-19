//go:build linux

package main

import (
 "errors"
 "fmt"
 "io"
 "os"
 "syscall"
)

// readPrivateFile pins the inode with O_NOFOLLOW before checking permissions.
// The descriptor is bounded and never exposes secret bytes in process arguments.
func readPrivateFile(name string, maxBytes int64, minBytes int) ([]byte, error) {
 if maxBytes <= 0 || minBytes < 0 || int64(minBytes) > maxBytes {
  return nil, errors.New("invalid private file limits")
 }
 fd, err := syscall.Open(name, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC|syscall.O_NONBLOCK, 0)
 if err != nil { return nil, fmt.Errorf("open private file: %w", err) }
 file := os.NewFile(uintptr(fd), name)
 defer file.Close()
 info, err := file.Stat()
 if err != nil { return nil, err }
 if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Mode()&os.ModeSetuid != 0 || info.Mode()&os.ModeSetgid != 0 {
  return nil, errors.New("private input must be a regular file with no group/other permissions")
 }
 if st, ok := info.Sys().(*syscall.Stat_t); ok && st.Nlink != 1 {
  return nil, errors.New("private input must not have hard links")
 }
 if info.Size() < int64(minBytes) || info.Size() > maxBytes {
  return nil, errors.New("private input size outside permitted bounds")
 }
 data, err := io.ReadAll(io.LimitReader(file, maxBytes+1))
 if err != nil { return nil, err }
 after, err := file.Stat()
 if err != nil { return nil, err }
 if !os.SameFile(info, after) || info.Size() != after.Size() || !info.ModTime().Equal(after.ModTime()) {
  return nil, errors.New("private input changed while reading")
 }
 if len(data) < minBytes || int64(len(data)) > maxBytes || int64(len(data)) != info.Size() {
  return nil, errors.New("private input length changed while reading")
 }
 return data, nil
}
