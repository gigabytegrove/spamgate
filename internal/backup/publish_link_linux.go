//go:build linux

package backup

import (
 "errors"
 "fmt"
 "os"
 "path/filepath"
 "syscall"
 "unsafe"
)

// publishBackupLink anchors both link names to one opened directory inode.
// Renaming the directory after opening cannot redirect publication to a
// replacement directory at the same pathname.
func publishBackupLink(source, destination string, expected os.FileInfo) error {
 parent := filepath.Dir(destination)
 if filepath.Dir(source) != parent {
  return errors.New("backup temporary file and destination must share a parent")
 }
 fd, err := syscall.Open(parent, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
 if err != nil { return fmt.Errorf("open backup destination directory: %w", err) }
 defer syscall.Close(fd)
 dir := os.NewFile(uintptr(fd), parent)
 actual, err := dir.Stat()
 if err != nil { return err }
 if !os.SameFile(expected, actual) {
  return errors.New("backup destination directory identity changed")
 }
 src, err := syscall.BytePtrFromString(filepath.Base(source))
 if err != nil { return err }
 dst, err := syscall.BytePtrFromString(filepath.Base(destination))
 if err != nil { return err }
 _, _, errno := syscall.Syscall6(syscall.SYS_LINKAT, uintptr(fd), uintptr(unsafe.Pointer(src)), uintptr(fd), uintptr(unsafe.Pointer(dst)), 0, 0)
 if errno != 0 { return fmt.Errorf("atomic backup publication: %w", errno) }
 // Durability must use the same directory descriptor as linkat. Opening
 // the pathname again would sync a replacement directory after a rename.
 if err := syscall.Fsync(fd); err != nil {
  return fmt.Errorf("backup published but destination directory sync failed: %w", err)
 }
 return nil
}
