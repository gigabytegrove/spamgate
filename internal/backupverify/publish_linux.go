//go:build linux

package backupverify

import (
 "fmt"
 "syscall"
 "unsafe"
 "runtime"
)

// publishRestore performs an atomic no-replace directory rename on Linux.
// RENAME_NOREPLACE is 1; syscall errors (including ENOSYS/EINVAL on old
// kernels/filesystems) fail closed rather than falling back to os.Rename.
func publishRestore(stage, target string) error {
 from, err := syscall.BytePtrFromString(stage)
 if err != nil { return err }
 to, err := syscall.BytePtrFromString(target)
 if err != nil { return err }
 const renameNoReplace = 1
 const atFDCWD = ^uintptr(99) // -100 as an unsigned machine word
 _, _, errno := syscall.RawSyscall6(syscall.SYS_RENAMEAT2,
  atFDCWD, uintptr(unsafe.Pointer(from)), atFDCWD,
  uintptr(unsafe.Pointer(to)), renameNoReplace, 0)
 if errno != 0 { return fmt.Errorf("atomic restore publish %q: %w", target, errno) }
 // Keep the Go-managed pathname buffers live through the syscall.
 runtime.KeepAlive(from)
 runtime.KeepAlive(to)
 return nil
}
