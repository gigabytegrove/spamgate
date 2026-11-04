//go:build !linux

package backup

import (
 "os"
)

// Non-Linux platforms retain the existing no-overwrite hard-link behavior.
// Linux uses directory-descriptor-relative publication instead.
func publishBackupLink(source, destination string, _ os.FileInfo) error {
 return os.Link(source, destination)
}
