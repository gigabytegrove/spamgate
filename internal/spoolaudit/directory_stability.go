package spoolaudit

import (
 "errors"
 "os"
)

// verifyAuditDirectoryPath ensures that a read-only audit did not traverse
// an inode detached from the pathname the operator requested. Live queue
// writes may change directory timestamps, so only identity and safety
// properties are stable enough to check.
func verifyAuditDirectoryPath(path string, opened os.FileInfo) error {
 current, err := os.Lstat(path)
 if err != nil {
  return errors.New("spool directory pathname disappeared")
 }
 if !current.IsDir() || current.Mode()&os.ModeSymlink != 0 {
  return errors.New("spool directory pathname is no longer a real directory")
 }
 if !os.SameFile(opened, current) {
  return errors.New("spool directory pathname was replaced")
 }
 if current.Mode().Perm()&0022 != 0 {
  return errors.New("spool directory became group/world writable")
 }
 return nil
}
