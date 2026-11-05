package spoolaudit

import (
 "io/fs"
 "os"
)

// unexpectedSpoolEntry examines objects outside the recognized published and
// pending filename namespaces. Regular unrelated files are ignored for
// compatibility; special objects are reported without following symlinks.
// DirEntry.Type may be unknown on some filesystems, so fall back to Lstat-like
// DirEntry.Info rather than treating an unknown type as a regular file.
func unexpectedSpoolEntry(entry os.DirEntry) (bool, string) {
 mode := entry.Type()
 if mode&fs.ModeType == 0 {
  info, err := entry.Info()
  if err != nil {
   return true, "cannot inspect unrecognized queue entry metadata"
  }
  mode = info.Mode()
 }
 if mode.IsRegular() {
  return false, ""
 }
 if mode&os.ModeSymlink != 0 {
  return true, "unrecognized symbolic link in delivery queue"
 }
 if mode.IsDir() {
  return true, "unrecognized directory in delivery queue"
 }
 return true, "unrecognized non-regular filesystem object in delivery queue"
}
