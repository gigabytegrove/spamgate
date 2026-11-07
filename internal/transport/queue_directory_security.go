package transport

import (
 "errors"
 "os"
)

// validateDeliveryQueueDirectory refuses a pre-existing spool with permissions
// that disclose accepted SMTP metadata to other local users. It deliberately
// does not chmod or chown: operators must inspect and correct the directory,
// and no running mail-host configuration is modified by this check.
func validateDeliveryQueueDirectory(info os.FileInfo) error {
 if info == nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
  return errors.New("delivery queue must be a real directory")
 }
 if info.Mode().Perm()&0077 != 0 {
  return errors.New("delivery queue directory exposes SMTP spool metadata to group or other users; set mode 0700 after reviewing ownership")
 }
 return nil
}
