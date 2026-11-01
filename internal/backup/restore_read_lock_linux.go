//go:build linux

package backup

import (
 "errors"
 "fmt"
 "os"
 "path/filepath"
 "syscall"
)

// acquireRestoreReadLock never creates a lock inode: a fresh restored tree
// must not acquire a root-owned .worker.lock that would later block the
// unprivileged service. Existing locks are exclusively flocked and checked
// for substitution. If absent, appearance during verification fails closed.
func acquireRestoreReadLock(root string) (func(), func() error, error) {
 path := filepath.Join(root, ".worker.lock")
 before, err := os.Lstat(path)
 if errors.Is(err, os.ErrNotExist) {
  check := func() error {
   _, err := os.Lstat(path)
   if errors.Is(err, os.ErrNotExist) { return nil }
   if err != nil { return err }
   return errors.New("worker lock appeared during restore verification")
  }
  return func(){}, check, nil
 }
 if err != nil { return nil, nil, err }
 if !before.Mode().IsRegular() { return nil, nil, errors.New("worker lock must be a regular file") }
 fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
 if err != nil { return nil, nil, err }
 f := os.NewFile(uintptr(fd), path)
 opened, err := f.Stat()
 if err != nil || !opened.Mode().IsRegular() || !os.SameFile(before, opened) {
  f.Close()
  return nil, nil, errors.New("worker lock changed during open")
 }
 if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
  f.Close()
  return nil, nil, fmt.Errorf("worker lock busy (stop SpamGate before verification): %w", err)
 }
 unlock := func(){ _ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN); _ = f.Close() }
 check := func() error {
  after, err := os.Lstat(path)
  if err != nil || !os.SameFile(opened, after) {
   return errors.New("worker lock changed during restore verification")
  }
  return nil
 }
 return unlock, check, nil
}
