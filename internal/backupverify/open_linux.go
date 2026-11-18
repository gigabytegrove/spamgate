//go:build linux

package backupverify

import (
 "fmt"
 "os"
 "strings"
 "syscall"
)

// openVerifiedPath walks from an opened directory descriptor, never resolving
// symlinks in any child component. This closes the check/open race that occurs
// when parent directories are inspected with Lstat and then reopened by name.
func openVerifiedPath(root, relative string) (*os.File, error) {
 dir, err := syscall.Open(root, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
 if err != nil { return nil, err }
 parts := strings.Split(relative, "/")
 for _, part := range parts[:len(parts)-1] {
  next, openErr := syscall.Openat(dir, part, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
  syscall.Close(dir)
  if openErr != nil { return nil, fmt.Errorf("unsafe backup directory %q: %w", relative, openErr) }
  dir = next
 }
 fd, err := syscall.Openat(dir, parts[len(parts)-1], syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
 syscall.Close(dir)
 if err != nil { return nil, err }
 var st syscall.Stat_t
 if err = syscall.Fstat(fd, &st); err != nil { syscall.Close(fd); return nil, err }
 if st.Mode&syscall.S_IFMT != syscall.S_IFREG {
  syscall.Close(fd)
  return nil, fmt.Errorf("backup entry %q is not a regular file", relative)
 }
 return os.NewFile(uintptr(fd), relative), nil
}
