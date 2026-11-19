//go:build linux && (amd64 || arm64)

package backupverify

import (
 "fmt"
 "os"
 "path/filepath"
 "runtime"
 "syscall"
 "unsafe"
)

// publishRestore pins the destination parent and uses descriptor-relative
// RENAME_NOREPLACE. Neither operand is resolved through a pathname parent
// after the directory descriptor is opened. No fallback to replace exists.
func publishRestore(stage, target string) error {
 sourceParent := filepath.Dir(stage)
 targetParent := filepath.Dir(target)
 if sourceParent != targetParent {
  return fmt.Errorf("restore stage and destination must share a parent")
 }
 fd, err := syscall.Open(targetParent, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
 if err != nil { return fmt.Errorf("open restore parent: %w", err) }
 defer syscall.Close(fd)

 // Ensure the pinned directory is still reachable at the requested path.
 // This check is diagnostic; the descriptor-relative syscall below is what
 // prevents an attacker from redirecting the actual rename to another parent.
 var pinned, current syscall.Stat_t
 if err := syscall.Fstat(fd, &pinned); err != nil { return err }
 if err := syscall.Lstat(targetParent, &current); err != nil { return err }
 if pinned.Dev != current.Dev || pinned.Ino != current.Ino {
  return fmt.Errorf("restore parent changed during publication")
 }
 from, err := syscall.BytePtrFromString(filepath.Base(stage))
 if err != nil { return err }
 to, err := syscall.BytePtrFromString(filepath.Base(target))
 if err != nil { return err }
 const renameNoReplace = 1
 _, _, errno := syscall.RawSyscall6(renameat2Syscall,
  uintptr(fd), uintptr(unsafe.Pointer(from)), uintptr(fd),
  uintptr(unsafe.Pointer(to)), renameNoReplace, 0)
 runtime.KeepAlive(from)
 runtime.KeepAlive(to)
 if errno != 0 { return fmt.Errorf("atomic restore publish %q: %w", target, errno) }
 // Sync the pinned directory rather than reopening an attacker-controlled path.
 if err := syscall.Fsync(fd); err != nil { return fmt.Errorf("sync published restore directory: %w", err) }
 return nil
}

// Ensure the syscall implementation is never silently replaced by a
// non-atomic os.Rename implementation.
var _ = os.ErrExist
