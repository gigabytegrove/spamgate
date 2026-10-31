//go:build !linux

package transport

import ("errors";"os")

// Linux-specific owner/link qualification is not claimed on other platforms.
func validateSpoolMetadata(_ string, inspected os.FileInfo) error {
 if !inspected.Mode().IsRegular() { return errors.New("spool object is not a regular file") }
 return nil
}
