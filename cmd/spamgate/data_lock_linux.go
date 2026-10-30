//go:build linux

package main

import (
 "errors"
 "fmt"
 "os"
 "path/filepath"
 "syscall"
)

// acquireInstanceLock protects the on-disk history journal from concurrently
// running workers. The launcher does not hold this lock: only the worker does.
// Keep the file (and fd) for the full worker lifetime; never unlink the inode.
func acquireInstanceLock(dir string) (func(), error) {
 if err := os.MkdirAll(dir, 0700); err != nil { return nil, fmt.Errorf("create SpamGate data directory: %w", err) }
 path := filepath.Join(dir, ".worker.lock")
 fd, err := syscall.Open(path, syscall.O_CREAT|syscall.O_RDWR|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0600)
 if err != nil { return nil, fmt.Errorf("open SpamGate instance lock: %w", err) }
 f := os.NewFile(uintptr(fd), path)
 if f == nil { _ = syscall.Close(fd); return nil, errors.New("unable to open SpamGate instance lock") }
 info, err := f.Stat()
 if err != nil || !info.Mode().IsRegular() {
  _ = f.Close()
  return nil, errors.New("SpamGate instance lock is not a regular file")
 }
 if err := syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
  _ = f.Close()
  if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
   return nil, fmt.Errorf("another SpamGate worker owns %s; refusing concurrent history access", dir)
  }
  return nil, fmt.Errorf("acquire SpamGate instance lock: %w", err)
 }
 return func() { _ = syscall.Flock(fd, syscall.LOCK_UN); _ = f.Close() }, nil
}
