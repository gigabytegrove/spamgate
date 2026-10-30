//go:build linux

package backup

import (
 "errors"
 "fmt"
 "os"
 "path/filepath"
 "syscall"
)

// acquireOfflineLock shares the worker's advisory .worker.lock, and holds it
// until backup publication completes. No Postfix or worker state is changed.
func acquireOfflineLock(source string) (func(), error) {
 path := filepath.Join(source, ".worker.lock")
 info, err := os.Lstat(path)
 if err == nil && !info.Mode().IsRegular() {
  return nil, errors.New("worker lock is not a regular file")
 }
 if err != nil && !errors.Is(err, os.ErrNotExist) { return nil, err }
 // O_NOFOLLOW closes the symlink-swap race between Lstat and open.
 fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_CREAT|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0600)
 if err != nil { return nil, err }
 f := os.NewFile(uintptr(fd), path)
 opened, err := f.Stat()
 if err != nil { f.Close(); return nil, err }
 if !opened.Mode().IsRegular() || (info != nil && !os.SameFile(info, opened)) {
  f.Close()
  return nil, errors.New("worker lock changed during open")
 }
 if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
  f.Close()
  return nil, fmt.Errorf("worker lock busy (stop SpamGate before backup): %w", err)
 }
 return func() { _ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN); _ = f.Close() }, nil
}
