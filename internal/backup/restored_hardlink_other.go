//go:build !linux

package backup

import "io/fs"

// On non-Linux platforms the standard FileInfo does not expose a portable
// link count. Linux is the production platform; do not infer link ownership.
func rejectRestoredHardlink(_ fs.FileInfo, _ string) error {
 return nil
}
