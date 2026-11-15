//go:build linux

package backup

import (
 "fmt"
 "io/fs"
 "syscall"
)

// An offline restored file must own its inode. A hard link can make an
// otherwise checksum-valid restored tree alias mutable data outside the root.
func rejectRestoredHardlink(info fs.FileInfo, relativePath string) error {
 stat, ok := info.Sys().(*syscall.Stat_t)
 if !ok {
  return fmt.Errorf("cannot inspect restored file link count: %q", relativePath)
 }
 if stat.Nlink != 1 {
  return fmt.Errorf("restored tree contains a hard-linked file: %q", relativePath)
 }
 return nil
}
