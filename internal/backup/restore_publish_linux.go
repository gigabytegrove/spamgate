//go:build linux && (amd64 || arm64)

package backup

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"unsafe"
)

// renameat2(RENAME_NOREPLACE) atomically publishes the already verified,
// fsynced restore tree without ever replacing a destination that appeared
// after the initial Lstat. os.Rename alone may replace a pre-existing path,
// while pre-creating an empty destination fails on some Linux filesystems.
func publishRestoredDirectory(stage, dest string) error {
	oldPath, err := syscall.BytePtrFromString(stage)
	if err != nil { return err }
	newPath, err := syscall.BytePtrFromString(dest)
	if err != nil { return err }
	const atFDCWD = ^uintptr(99) // AT_FDCWD == -100
	const renameNoReplace = uintptr(1)
	var syscallNumber uintptr
	switch runtime.GOARCH {
	case "amd64":
		syscallNumber = 316 // Linux x86_64 renameat2
	case "arm64":
		syscallNumber = 276 // Linux aarch64 renameat2
	default:
		return fmt.Errorf("atomic no-replace restore is unsupported on %s", runtime.GOARCH)
	}
	_, _, errno := syscall.RawSyscall6(
		syscallNumber,
		atFDCWD, uintptr(unsafe.Pointer(oldPath)),
		atFDCWD, uintptr(unsafe.Pointer(newPath)),
		renameNoReplace, 0,
	)
	runtime.KeepAlive(oldPath)
	runtime.KeepAlive(newPath)
	if errno != 0 {
		return fmt.Errorf("cannot publish restore without replacing destination: %w", errno)
	}
	parent, err := os.Open(filepath.Dir(dest))
	if err != nil { return fmt.Errorf("restore published but parent directory sync failed: %w", err) }
	syncErr := parent.Sync()
	closeErr := parent.Close()
	if syncErr != nil { return fmt.Errorf("restore published but parent directory sync failed: %w", syncErr) }
	return closeErr
}
